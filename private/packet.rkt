#lang racket

(provide (all-defined-out))

(require "options.rkt")

(define SIZE-SIZE 4)
(define ID-SIZE 4)
(define TYPE-SIZE 4)

(define AUTH-TYPE 3)
(define AUTH-RESPONSE-TYPE 2)
(define EXECCOMMAND-TYPE 2)
(define RESPONSE-VALUE-TYPE 0)

(struct packet [id] #:transparent)
(struct auth-packet packet [password] #:transparent)
(struct auth-response-packet packet [authenticated?] #:transparent)
(struct execcommand-packet packet [command] #:transparent)
(struct response-value-packet packet [response] #:transparent)

(define (packet-size pkt)
  (+ 1 #| final terminating byte |#
     ID-SIZE TYPE-SIZE
     (match pkt
       [(struct* auth-packet ([password password]))
        (add1 (string-length password))]
       [(struct* auth-response-packet ())
        1 #| Empty body |#]
       [(struct* execcommand-packet ([command command]))
        (add1 (string-length command))]
       [(struct* response-value-packet ([response response]))
        (add1 (string-length response))])))

(define (body->string b)
  (if (< (bytes-length b) 2)
      ""
      (bytes->string/utf-8 b #f 0 (sub1 (bytes-length b)))))

(define (string->body s)
  (bytes-append (string->bytes/utf-8 s) #"\x00"))

(define (read-packet ip)
  (let/ec escape
    (define size (match (read-bytes SIZE-SIZE ip)
                   [(? eof-object? e) (escape e)]
                   [b (integer-bytes->integer b #t #f)]))
    (define b (match (read-bytes size ip)
                [(? eof-object? e) (escape e)]
                [b b]))
    (define id (integer-bytes->integer (subbytes b 0 ID-SIZE) #t #f))
    (define body (subbytes b 8 (sub1 (bytes-length b))))
    (match (integer-bytes->integer (subbytes b ID-SIZE (+ ID-SIZE TYPE-SIZE)) #t #f)
      [(? (curry = AUTH-TYPE))
       (auth-packet id (body->string body))]
      [(or (? (curry = AUTH-RESPONSE-TYPE))
           (? (curry = EXECCOMMAND-TYPE)))
       (if (equal? (mode) 'client)
           (auth-response-packet id (not (= -1 id)))
           (execcommand-packet id (body->string body)))]
      [(? (curry = RESPONSE-VALUE-TYPE))
       (response-value-packet id (body->string body))])))

(define (write-packet pkt op)
  (write-bytes (integer->integer-bytes (packet-size pkt) 4 #t #f) op)
  (write-bytes (integer->integer-bytes (packet-id pkt) 4 #t #f) op)
  (define-values (type body)
    (match pkt
      [(struct* auth-packet ([password password]))
       (values AUTH-TYPE (string->body password))]
      [(struct* auth-response-packet ())
       (values AUTH-RESPONSE-TYPE #"\x00")]
      [(struct* execcommand-packet ([command command]))
       (values EXECCOMMAND-TYPE (string->body command))]
      [(struct* response-value-packet ([response response]))
       (values RESPONSE-VALUE-TYPE (string->body response))]))
  (write-bytes (integer->integer-bytes type 4 #t #f) op)
  (write-bytes body op)
  (write-byte #x00 op)
  (flush-output op)
  (void))

(module+ test
  (require rackunit)
  (define sample-data (call-with-input-file "sample-data.rktd" read))
  (define packets (hash-ref sample-data 'packets))
  (test-case "packet-size"
    (check-equal? (packet-size (auth-packet 123 "passwrd")) #x11 "auth-packet")
    (check-equal? (packet-size (auth-response-packet 123 #t)) #x0a "auth-response-packet")
    (check-equal? (packet-size (execcommand-packet 123 "echo HLSW: Test")) #x19 "execcommand-packet")
    (check-equal? (packet-size (response-value-packet 123 "a response")) 20 "response-value-packet"))
  (test-case "read-packet"
    (check-equal? (call-with-input-bytes (hash-ref packets 'auth) read-packet)
                  (auth-packet 0 "passwrd")
                  "auth-packet")
    (parameterize ([mode 'client])
      (check-equal? (call-with-input-bytes (hash-ref packets 'auth-response) read-packet)
                    (auth-response-packet 0 #t)
                    "auth-response-packet/client"))
    (check-equal? (call-with-input-bytes (hash-ref packets 'empty-response-value) read-packet)
                  (response-value-packet 0 "")
                  "response-value-packet/empty")
    (parameterize ([mode 'server])
      (check-equal? (call-with-input-bytes (hash-ref packets 'execcommand) read-packet)
                    (execcommand-packet 0 "echo HLSW: Test")))))
