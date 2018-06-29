#lang racket

(provide (prefix-out simple- (all-defined-out)))

(require "packet.rkt"
         "options.rkt")

(mode 'client)

#|

API:

rcon-open addr port password(?)
rcon-close rcon-connection
rcon-execute rcon-connection command

|#

(struct rcon-connection (input-port output-port) #:transparent)

(define (rcon-open address port [password #f])
  (define-values (ip op) (tcp-connect address port))
  (when password
    (write-packet (auth-packet 0 password) op)
    (match (read-packet ip)
      [(? eof-object?) (raise-user-error 'rcon-open "Error authenticating - early EOF")]
      [(struct* auth-response-packet ([authenticated? authenticated?]))
       (unless authenticated?
         (close-input-port ip)
         (close-output-port op)
         (raise-user-error 'rcon-open "Error authenticating - bad password"))]))
  (rcon-connection ip op))

(define (rcon-close rc)
  (match-define (rcon-connection ip op) rc)
  (close-input-port ip)
  (close-output-port op))

(define (rcon-execute rc command)
  (match-define (rcon-connection ip op) rc)
  (define n (random  (- #xffff) #xffff))
  (write-packet (execcommand-packet n command) op)
  (match (read-packet ip)
    [(and p (struct* response-value-packet ([response response]))
          (struct* packet ([id id])))
     (unless (= id n)
       (raise-user-error 'rcon-execute "Got back bad packet - ~v" p))
     response]))
