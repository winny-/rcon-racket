#lang racket

(provide (all-defined-out))

(define mode (make-parameter 'client
                             (λ (p)
                               (unless ((or/c 'client 'server) p)
                                 (error 'mode-guard "Should be either 'client or 'server"))
                               p)))
;(define multiple-response-strategy (make-parameter 'default))
