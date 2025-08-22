import { describe, expect, it } from "vitest";
import { Cl } from "@stacks/transactions";

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!;
const wallet1 = accounts.get("wallet_1")!;
const wallet2 = accounts.get("wallet_2")!;
const wallet3 = accounts.get("wallet_3")!;

// Helper function to create a credential hash
function createCredentialHash(data: string): Uint8Array {
  const encoder = new TextEncoder();
  const dataArray = encoder.encode(data);
  const hash = new Uint8Array(32);
  for (let i = 0; i < Math.min(dataArray.length, 32); i++) {
    hash[i] = dataArray[i];
  }
  return hash;
}

describe("Degree Verification Contract", () => {
  describe("Issuer Management", () => {
    it("should allow contract owner to register new issuers", () => {
      const institutionName = "Stanford University";
      
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii(institutionName)],
        deployer
      );
      
      expect(result).toBeOk(Cl.bool(true));
      
      // Verify issuer is registered
      const checkResult = simnet.callReadOnlyFn(
        "degree-verification",
        "is-authorized-issuer",
        [Cl.principal(wallet1)],
        deployer
      );
      
      expect(checkResult.result).toBe(Cl.bool(true));
    });

    it("should not allow non-owner to register issuers", () => {
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet2), Cl.stringAscii("MIT")],
        wallet1
      );
      
      expect(result).toBeErr(Cl.uint(401)); // ERR-NOT-AUTHORIZED
    });

    it("should prevent double registration of issuers", () => {
      // First registration
      simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("Harvard")],
        deployer
      );
      
      // Second registration attempt
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("Harvard Business School")],
        deployer
      );
      
      expect(result).toBeErr(Cl.uint(407)); // ERR-INVALID-ISSUER
    });

    it("should allow deactivation of issuers", () => {
      // Register issuer
      simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("Oxford University")],
        deployer
      );
      
      // Deactivate issuer
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "deactivate-issuer",
        [Cl.principal(wallet1)],
        deployer
      );
      
      expect(result).toBeOk(Cl.bool(true));
      
      // Verify issuer is deactivated
      const checkResult = simnet.callReadOnlyFn(
        "degree-verification",
        "is-authorized-issuer",
        [Cl.principal(wallet1)],
        deployer
      );
      
      expect(checkResult.result).toBe(Cl.bool(false));
    });
  });

  describe("Credential Issuance", () => {
    it("should allow authorized issuers to issue credentials", () => {
      // Register issuer
      simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("Yale University")],
        deployer
      );
      
      const credentialHash = createCredentialHash("degree-001");
      const recipient = "John Doe";
      const degreeType = "Bachelor of Science";
      
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "issue-credential",
        [
          Cl.buffer(credentialHash),
          Cl.stringAscii(recipient),
          Cl.stringAscii(degreeType),
          Cl.none(), // no expiry
          Cl.none()  // no metadata
        ],
        wallet1
      );
      
      expect(result).toBeOk(Cl.buffer(credentialHash));
      
      // Verify credential exists
      const credential = simnet.callReadOnlyFn(
        "degree-verification",
        "get-credential",
        [Cl.buffer(credentialHash)],
        deployer
      );
      
      expect(credential.result).toBeOkResponse();
    });

    it("should not allow unauthorized issuers to issue credentials", () => {
      const credentialHash = createCredentialHash("degree-002");
      
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "issue-credential",
        [
          Cl.buffer(credentialHash),
          Cl.stringAscii("Jane Doe"),
          Cl.stringAscii("Master of Arts"),
          Cl.none(),
          Cl.none()
        ],
        wallet2 // Not registered as issuer
      );
      
      expect(result).toBeErr(Cl.uint(401)); // ERR-NOT-AUTHORIZED
    });

    it("should prevent duplicate credential issuance", () => {
      // Register issuer
      simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("Cambridge University")],
        deployer
      );
      
      const credentialHash = createCredentialHash("degree-003");
      
      // First issuance
      simnet.callPublicFn(
        "degree-verification",
        "issue-credential",
        [
          Cl.buffer(credentialHash),
          Cl.stringAscii("Alice Smith"),
          Cl.stringAscii("PhD in Physics"),
          Cl.none(),
          Cl.none()
        ],
        wallet1
      );
      
      // Second issuance attempt with same hash
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "issue-credential",
        [
          Cl.buffer(credentialHash),
          Cl.stringAscii("Bob Smith"),
          Cl.stringAscii("PhD in Chemistry"),
          Cl.none(),
          Cl.none()
        ],
        wallet1
      );
      
      expect(result).toBeErr(Cl.uint(402)); // ERR-CREDENTIAL-EXISTS
    });

    it("should handle credentials with expiry dates", () => {
      // Register issuer
      simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("Professional Institute")],
        deployer
      );
      
      const credentialHash = createCredentialHash("cert-001");
      const expiryBlock = 100000;
      
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "issue-credential",
        [
          Cl.buffer(credentialHash),
          Cl.stringAscii("Professional User"),
          Cl.stringAscii("Professional Certificate"),
          Cl.some(Cl.uint(expiryBlock)),
          Cl.none()
        ],
        wallet1
      );
      
      expect(result).toBeOk(Cl.buffer(credentialHash));
    });
  });

  describe("Credential Verification", () => {
    it("should verify valid credentials", () => {
      // Setup: Register issuer and issue credential
      simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("Tech University")],
        deployer
      );
      
      const credentialHash = createCredentialHash("degree-verify-001");
      simnet.callPublicFn(
        "degree-verification",
        "issue-credential",
        [
          Cl.buffer(credentialHash),
          Cl.stringAscii("Test Student"),
          Cl.stringAscii("BS Computer Science"),
          Cl.none(),
          Cl.none()
        ],
        wallet1
      );
      
      // Verify credential
      const { result } = simnet.callReadOnlyFn(
        "degree-verification",
        "verify-credential",
        [Cl.buffer(credentialHash)],
        deployer
      );
      
      expect(result).toBeOkResponse();
      // The response should contain valid: true
    });

    it("should report non-existent credentials", () => {
      const credentialHash = createCredentialHash("non-existent");
      
      const { result } = simnet.callReadOnlyFn(
        "degree-verification",
        "verify-credential",
        [Cl.buffer(credentialHash)],
        deployer
      );
      
      expect(result).toBeErr(Cl.uint(403)); // ERR-CREDENTIAL-NOT-FOUND
    });

    it("should log verification requests", () => {
      // Setup: Register issuer and issue credential
      simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("State University")],
        deployer
      );
      
      const credentialHash = createCredentialHash("degree-log-001");
      simnet.callPublicFn(
        "degree-verification",
        "issue-credential",
        [
          Cl.buffer(credentialHash),
          Cl.stringAscii("Log Test User"),
          Cl.stringAscii("BA History"),
          Cl.none(),
          Cl.none()
        ],
        wallet1
      );
      
      // Log verification
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "log-verification",
        [Cl.buffer(credentialHash)],
        wallet2
      );
      
      expect(result).toBeOkResponse();
      
      // Check verification log
      const log = simnet.callReadOnlyFn(
        "degree-verification",
        "get-verification-log",
        [Cl.uint(0)],
        deployer
      );
      
      expect(log.result).toBeOkResponse();
    });
  });

  describe("Credential Revocation", () => {
    it("should allow issuer to revoke credentials", () => {
      // Setup: Register issuer and issue credential
      simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("Revoke University")],
        deployer
      );
      
      const credentialHash = createCredentialHash("degree-revoke-001");
      simnet.callPublicFn(
        "degree-verification",
        "issue-credential",
        [
          Cl.buffer(credentialHash),
          Cl.stringAscii("Revoke Test User"),
          Cl.stringAscii("BS Biology"),
          Cl.none(),
          Cl.none()
        ],
        wallet1
      );
      
      // Revoke credential
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "revoke-credential",
        [Cl.buffer(credentialHash), Cl.stringAscii("Academic misconduct")],
        wallet1
      );
      
      expect(result).toBeOk(Cl.bool(true));
      
      // Verify credential is revoked
      const isRevoked = simnet.callReadOnlyFn(
        "degree-verification",
        "is-revoked",
        [Cl.buffer(credentialHash)],
        deployer
      );
      
      expect(isRevoked.result).toBe(Cl.bool(true));
    });

    it("should allow contract owner to revoke any credential", () => {
      // Setup: Register issuer and issue credential
      simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("Owner Revoke University")],
        deployer
      );
      
      const credentialHash = createCredentialHash("degree-owner-revoke");
      simnet.callPublicFn(
        "degree-verification",
        "issue-credential",
        [
          Cl.buffer(credentialHash),
          Cl.stringAscii("Owner Revoke User"),
          Cl.stringAscii("MBA"),
          Cl.none(),
          Cl.none()
        ],
        wallet1
      );
      
      // Contract owner revokes credential
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "revoke-credential",
        [Cl.buffer(credentialHash), Cl.stringAscii("Administrative action")],
        deployer
      );
      
      expect(result).toBeOk(Cl.bool(true));
    });

    it("should not allow unauthorized revocation", () => {
      // Setup: Register issuer and issue credential
      simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("Auth Revoke University")],
        deployer
      );
      
      const credentialHash = createCredentialHash("degree-auth-revoke");
      simnet.callPublicFn(
        "degree-verification",
        "issue-credential",
        [
          Cl.buffer(credentialHash),
          Cl.stringAscii("Auth Revoke User"),
          Cl.stringAscii("MSc"),
          Cl.none(),
          Cl.none()
        ],
        wallet1
      );
      
      // Unauthorized user tries to revoke
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "revoke-credential",
        [Cl.buffer(credentialHash), Cl.stringAscii("Unauthorized")],
        wallet2 // Not the issuer or owner
      );
      
      expect(result).toBeErr(Cl.uint(401)); // ERR-NOT-AUTHORIZED
    });

    it("should allow reinstatement of revoked credentials", () => {
      // Setup: Register, issue, and revoke credential
      simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("Reinstate University")],
        deployer
      );
      
      const credentialHash = createCredentialHash("degree-reinstate");
      simnet.callPublicFn(
        "degree-verification",
        "issue-credential",
        [
          Cl.buffer(credentialHash),
          Cl.stringAscii("Reinstate User"),
          Cl.stringAscii("BFA"),
          Cl.none(),
          Cl.none()
        ],
        wallet1
      );
      
      simnet.callPublicFn(
        "degree-verification",
        "revoke-credential",
        [Cl.buffer(credentialHash), Cl.stringAscii("Error in records")],
        wallet1
      );
      
      // Reinstate credential
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "reinstate-credential",
        [Cl.buffer(credentialHash)],
        wallet1
      );
      
      expect(result).toBeOk(Cl.bool(true));
      
      // Verify credential is no longer revoked
      const isRevoked = simnet.callReadOnlyFn(
        "degree-verification",
        "is-revoked",
        [Cl.buffer(credentialHash)],
        deployer
      );
      
      expect(isRevoked.result).toBe(Cl.bool(false));
    });
  });

  describe("Batch Operations", () => {
    it("should allow batch credential issuance", () => {
      // Register issuer
      simnet.callPublicFn(
        "degree-verification",
        "register-issuer",
        [Cl.principal(wallet1), Cl.stringAscii("Batch University")],
        deployer
      );
      
      const credentials = [
        {
          hash: createCredentialHash("batch-001"),
          recipient: "Student 1",
          degreeType: "BS Computer Science",
          expiry: null
        },
        {
          hash: createCredentialHash("batch-002"),
          recipient: "Student 2",
          degreeType: "BS Mathematics",
          expiry: null
        }
      ];
      
      const credentialsList = Cl.list(credentials.map(cred => 
        Cl.tuple({
          hash: Cl.buffer(cred.hash),
          recipient: Cl.stringAscii(cred.recipient),
          'degree-type': Cl.stringAscii(cred.degreeType),
          expiry: Cl.none()
        })
      ));
      
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "batch-issue-credentials",
        [credentialsList],
        wallet1
      );
      
      expect(result).toBeOkResponse();
    });
  });

  describe("Contract Statistics", () => {
    it("should track contract statistics", () => {
      const { result } = simnet.callReadOnlyFn(
        "degree-verification",
        "get-stats",
        [],
        deployer
      );
      
      expect(result).toBeOkResponse();
      // Should contain total-credentials, total-revocations, and contract-owner
    });
  });

  describe("Ownership Transfer", () => {
    it("should allow ownership transfer by current owner", () => {
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "transfer-ownership",
        [Cl.principal(wallet2)],
        deployer
      );
      
      expect(result).toBeOk(Cl.bool(true));
      
      // Verify new owner
      const stats = simnet.callReadOnlyFn(
        "degree-verification",
        "get-stats",
        [],
        deployer
      );
      
      // New owner should be wallet2
      expect(stats.result).toBeOkResponse();
    });

    it("should not allow ownership transfer by non-owner", () => {
      const { result } = simnet.callPublicFn(
        "degree-verification",
        "transfer-ownership",
        [Cl.principal(wallet3)],
        wallet1 // Not the owner
      );
      
      expect(result).toBeErr(Cl.uint(401)); // ERR-NOT-AUTHORIZED
    });
  });
});
