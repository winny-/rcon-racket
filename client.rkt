#lang racket

(provide (prefix-out (all-defined-out)))

(require "private/packet.rkt")

(define multiple-response-mode (make-parameter 'source))
(define multiple-response-joiner (make-parameter ""))

(struct connection [hostname port input-port output-port] #:transparent)

(define (connect hostname port [password #f])
  (define-values (ip op) (tcp-connect hostname port))
  (when password
    (write-packet (auth-packet 0 password) op)
    (match (read-packet ip)
      [(? eof-object?) (raise-user-error "Early end-of-file after sending password")]
      [(struct* auth-response-packet ([authenticated? authenticated?]))
       (unless authenticated?
         (raise-user-error "Wrong password"))]
      [a (raise-user-error "Weird response: ~v" a)]))
  (connection hostname port ip op))

(define (close connection)
  (close-output-port (connection-output-port connection)))

(define (execute conn command)
  (match-define (struct* connection ([input-port ip] [output-port op])) conn)
  (write-packet (execcommand-packet 1 command) op)
  (match (multiple-response-mode)
    ['source (write-packet (response-value-packet 2 "") op)]
    [(? string? s) (write-packet (execcommand-packet 2 command) op)])
  (let loop ([responses '()])
    (match (read-packet ip)
      [(? eof-object?) (raise-user-error "Early end-of-file while awaiting response")]
      [(and (struct* packet ([id 1)))
            (struct* response-value-packet ([response response])))
       (loop (cons response responses))]
      [(and (struct* packet ([id 2]))
            )]
