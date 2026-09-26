package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type spool struct {
	io.Reader
	file    *os.File
	once    sync.Once
	onClose func()
}

func (s *spool) Close() error {
	var err error
	s.once.Do(func() {
		if s.file != nil {
			err = s.file.Close()
			os.Remove(s.file.Name())
		}
		if s.onClose != nil {
			s.onClose()
		}
	})
	return err
}
func (s *spool) Rewind() error {
	if s.file != nil {
		_, e := s.file.Seek(0, io.SeekStart)
		return e
	}
	_, e := s.Reader.(*bytes.Reader).Seek(0, io.SeekStart)
	return e
}

var errBodyLimit = errors.New("request body limit exceeded")

func bufferBody(body io.Reader, limit int64, tmp string) (*spool, int64, error) {
	var memory bytes.Buffer
	buf := make([]byte, 32*1024)
	var file *os.File
	var n int64
	cleanup := func() {
		if file != nil {
			file.Close()
			os.Remove(file.Name())
		}
	}
	for {
		read, e := body.Read(buf)
		if read > 0 {
			n += int64(read)
			if n > limit {
				cleanup()
				return nil, n, errBodyLimit
			}
			if file == nil && memory.Len()+read <= 128*1024 {
				memory.Write(buf[:read])
			} else {
				if file == nil {
					file, e = os.CreateTemp(tmp, "body-*")
					if e != nil {
						return nil, n, e
					}
					if _, e = file.Write(memory.Bytes()); e != nil {
						cleanup()
						return nil, n, e
					}
					memory.Reset()
				}
				if _, e = file.Write(buf[:read]); e != nil {
					cleanup()
					return nil, n, e
				}
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			cleanup()
			return nil, n, e
		}
	}
	s := &spool{file: file}
	if file != nil {
		if _, e := file.Seek(0, io.SeekStart); e != nil {
			cleanup()
			return nil, n, e
		}
		s.Reader = file
	} else {
		s.Reader = bytes.NewReader(memory.Bytes())
	}
	return s, n, nil
}

type idleBody struct {
	io.ReadCloser
	rc        *http.ResponseController
	idle      time.Duration
	remaining int64
	exceeded  atomic.Bool
}

func (b *idleBody) Read(p []byte) (int, error) {
	if b.remaining < 0 {
		return 0, errBodyLimit
	}
	b.rc.SetReadDeadline(time.Now().Add(b.idle))
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, e := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		b.exceeded.Store(true)
		// Do not forward the byte used to detect that the limit was exceeded.
		return n + int(b.remaining), errBodyLimit
	}
	return n, e
}
func (b *idleBody) Close() error { b.rc.SetReadDeadline(time.Time{}); return b.ReadCloser.Close() }

type idleResponseBody struct {
	io.ReadCloser
	idle   time.Duration
	cancel func()
}

func (b *idleResponseBody) Read(p []byte) (int, error) {
	timer := time.AfterFunc(b.idle, b.cancel)
	n, e := b.ReadCloser.Read(p)
	timer.Stop()
	return n, e
}

type idleDuplex struct {
	io.ReadWriteCloser
	idle   time.Duration
	cancel func()
}

func (b *idleDuplex) Read(p []byte) (int, error) {
	t := time.AfterFunc(b.idle, b.cancel)
	n, e := b.ReadWriteCloser.Read(p)
	t.Stop()
	return n, e
}

type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
	idle   time.Duration
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *responseWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != 101 {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	if w.status != 0 {
		return
	}
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *responseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(w.idle))
	n, e := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, e
}
