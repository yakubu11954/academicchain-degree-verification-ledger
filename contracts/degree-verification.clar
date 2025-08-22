;; AcademicChain Degree Verification Smart Contract
;; A tamper-evident degree and certificate verification system

;; Constants
(define-constant ERR-NOT-AUTHORIZED (err u401))
(define-constant ERR-CREDENTIAL-EXISTS (err u402))
(define-constant ERR-CREDENTIAL-NOT-FOUND (err u403))
(define-constant ERR-INVALID-HASH (err u404))
(define-constant ERR-ALREADY-REVOKED (err u405))
(define-constant ERR-NOT-REVOKED (err u406))
(define-constant ERR-INVALID-ISSUER (err u407))
(define-constant ERR-EXPIRED-CREDENTIAL (err u408))

;; Data Variables
(define-data-var contract-owner principal tx-sender)
(define-data-var total-credentials uint u0)
(define-data-var total-revocations uint u0)

;; Data Maps
;; Store credential hashes with metadata
(define-map credentials
    { credential-hash: (buff 32) }
    {
        issuer: principal,
        recipient: (string-ascii 100),
        institution: (string-ascii 100),
        degree-type: (string-ascii 50),
        issue-date: uint,
        expiry-date: (optional uint),
        metadata-hash: (optional (buff 32)),
        timestamp: uint
    }
)

;; Store revoked credentials
(define-map revoked-credentials
    { credential-hash: (buff 32) }
    {
        revoked-by: principal,
        revocation-date: uint,
        reason: (string-ascii 200)
    }
)

;; Store authorized issuers (institutions)
(define-map authorized-issuers
    { issuer: principal }
    {
        institution-name: (string-ascii 100),
        authorized-date: uint,
        is-active: bool
    }
)

;; Store verification requests for audit trail
(define-map verification-log
    { request-id: uint }
    {
        credential-hash: (buff 32),
        verifier: principal,
        verification-time: uint,
        result: bool
    }
)

(define-data-var verification-counter uint u0)

;; Read-only functions

;; Get credential details
(define-read-only (get-credential (credential-hash (buff 32)))
    (map-get? credentials { credential-hash: credential-hash })
)

;; Check if credential is revoked
(define-read-only (is-revoked (credential-hash (buff 32)))
    (is-some (map-get? revoked-credentials { credential-hash: credential-hash }))
)

;; Get revocation details
(define-read-only (get-revocation-details (credential-hash (buff 32)))
    (map-get? revoked-credentials { credential-hash: credential-hash })
)

;; Check if an issuer is authorized
(define-read-only (is-authorized-issuer (issuer principal))
    (match (map-get? authorized-issuers { issuer: issuer })
        issuer-data (get is-active issuer-data)
        false
    )
)

;; Get issuer details
(define-read-only (get-issuer-details (issuer principal))
    (map-get? authorized-issuers { issuer: issuer })
)

;; Verify a credential (comprehensive check)
(define-read-only (verify-credential (credential-hash (buff 32)))
    (match (map-get? credentials { credential-hash: credential-hash })
        credential-data
        (if (is-revoked credential-hash)
            (ok { 
                valid: false, 
                reason: "Credential has been revoked",
                credential: credential-data,
                revocation: (get-revocation-details credential-hash)
            })
            ;; Check if credential has expired
            (match (get expiry-date credential-data)
                expiry
                (if (> stacks-block-height expiry)
                    (ok { 
                        valid: false, 
                        reason: "Credential has expired",
                        credential: credential-data,
                        revocation: none
                    })
                    (ok { 
                        valid: true, 
                        reason: "Credential is valid",
                        credential: credential-data,
                        revocation: none
                    })
                )
                ;; No expiry date, credential is valid
                (ok { 
                    valid: true, 
                    reason: "Credential is valid",
                    credential: credential-data,
                    revocation: none
                })
            )
        )
        (err ERR-CREDENTIAL-NOT-FOUND)
    )
)

;; Get contract statistics
(define-read-only (get-stats)
    {
        total-credentials: (var-get total-credentials),
        total-revocations: (var-get total-revocations),
        contract-owner: (var-get contract-owner)
    }
)

;; Get verification log entry
(define-read-only (get-verification-log (request-id uint))
    (map-get? verification-log { request-id: request-id })
)

;; Public functions

;; Register a new authorized issuer (only contract owner)
(define-public (register-issuer (issuer principal) (institution-name (string-ascii 100)))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (not (is-authorized-issuer issuer)) ERR-INVALID-ISSUER)
        (map-set authorized-issuers
            { issuer: issuer }
            {
                institution-name: institution-name,
                authorized-date: stacks-block-height,
                is-active: true
            }
        )
        (ok true)
    )
)

;; Deactivate an issuer (only contract owner)
(define-public (deactivate-issuer (issuer principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (match (map-get? authorized-issuers { issuer: issuer })
            issuer-data
            (begin
                (map-set authorized-issuers
                    { issuer: issuer }
                    (merge issuer-data { is-active: false })
                )
                (ok true)
            )
            ERR-INVALID-ISSUER
        )
    )
)

;; Issue a new credential (only authorized issuers)
(define-public (issue-credential 
    (credential-hash (buff 32))
    (recipient (string-ascii 100))
    (degree-type (string-ascii 50))
    (expiry-date (optional uint))
    (metadata-hash (optional (buff 32)))
)
    (begin
        ;; Check if issuer is authorized
        (asserts! (is-authorized-issuer tx-sender) ERR-NOT-AUTHORIZED)
        
        ;; Check if credential already exists
        (asserts! (is-none (map-get? credentials { credential-hash: credential-hash })) ERR-CREDENTIAL-EXISTS)
        
        ;; Get issuer institution name
        (match (map-get? authorized-issuers { issuer: tx-sender })
            issuer-data
            (begin
                ;; Store credential
                (map-set credentials
                    { credential-hash: credential-hash }
                    {
                        issuer: tx-sender,
                        recipient: recipient,
                        institution: (get institution-name issuer-data),
                        degree-type: degree-type,
                        issue-date: stacks-block-height,
                        expiry-date: expiry-date,
                        metadata-hash: metadata-hash,
                        timestamp: stacks-block-height
                    }
                )
                
                ;; Update counter
                (var-set total-credentials (+ (var-get total-credentials) u1))
                
                (ok credential-hash)
            )
            ERR-INVALID-ISSUER
        )
    )
)

;; Revoke a credential (only by original issuer or contract owner)
(define-public (revoke-credential (credential-hash (buff 32)) (reason (string-ascii 200)))
    (match (map-get? credentials { credential-hash: credential-hash })
        credential-data
        (begin
            ;; Check authorization (must be issuer or contract owner)
            (asserts! 
                (or 
                    (is-eq tx-sender (get issuer credential-data))
                    (is-eq tx-sender (var-get contract-owner))
                )
                ERR-NOT-AUTHORIZED
            )
            
            ;; Check if already revoked
            (asserts! (not (is-revoked credential-hash)) ERR-ALREADY-REVOKED)
            
            ;; Add to revocation list
            (map-set revoked-credentials
                { credential-hash: credential-hash }
                {
                    revoked-by: tx-sender,
                    revocation-date: stacks-block-height,
                    reason: reason
                }
            )
            
            ;; Update counter
            (var-set total-revocations (+ (var-get total-revocations) u1))
            
            (ok true)
        )
        ERR-CREDENTIAL-NOT-FOUND
    )
)

;; Reinstate a revoked credential (only by original issuer or contract owner)
(define-public (reinstate-credential (credential-hash (buff 32)))
    (match (map-get? credentials { credential-hash: credential-hash })
        credential-data
        (begin
            ;; Check authorization
            (asserts! 
                (or 
                    (is-eq tx-sender (get issuer credential-data))
                    (is-eq tx-sender (var-get contract-owner))
                )
                ERR-NOT-AUTHORIZED
            )
            
            ;; Check if credential is revoked
            (asserts! (is-revoked credential-hash) ERR-NOT-REVOKED)
            
            ;; Remove from revocation list
            (map-delete revoked-credentials { credential-hash: credential-hash })
            
            ;; Update counter
            (var-set total-revocations (- (var-get total-revocations) u1))
            
            (ok true)
        )
        ERR-CREDENTIAL-NOT-FOUND
    )
)

;; Log a verification request (for audit trail)
(define-public (log-verification (credential-hash (buff 32)))
    (let
        (
            (request-id (var-get verification-counter))
            (verification-result (verify-credential credential-hash))
        )
        (match verification-result
            success-data
            (begin
                (map-set verification-log
                    { request-id: request-id }
                    {
                        credential-hash: credential-hash,
                        verifier: tx-sender,
                        verification-time: stacks-block-height,
                        result: (get valid success-data)
                    }
                )
                (var-set verification-counter (+ request-id u1))
                (ok { request-id: request-id, verification: success-data })
            )
            error-code
            (err error-code)
        )
    )
)

;; Batch issue credentials (for efficiency)
(define-public (batch-issue-credentials (credentials-list (list 10 { 
    hash: (buff 32), 
    recipient: (string-ascii 100), 
    degree-type: (string-ascii 50),
    expiry: (optional uint)
})))
    (begin
        ;; Check if issuer is authorized
        (asserts! (is-authorized-issuer tx-sender) ERR-NOT-AUTHORIZED)
        
        (ok (map process-batch-credential credentials-list))
    )
)

;; Helper function for batch processing
(define-private (process-batch-credential (credential-info { 
    hash: (buff 32), 
    recipient: (string-ascii 100), 
    degree-type: (string-ascii 50),
    expiry: (optional uint)
}))
    (issue-credential 
        (get hash credential-info)
        (get recipient credential-info)
        (get degree-type credential-info)
        (get expiry credential-info)
        none
    )
)

;; Transfer contract ownership
(define-public (transfer-ownership (new-owner principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (var-set contract-owner new-owner)
        (ok true)
    )
)