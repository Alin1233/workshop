import { describe, expect, it } from "vitest";
import { LABEL_MAX, loginSchema, registerSchema, transferSchema, validate } from "./validation";

// Cette méthode permet de valider un virement à partir d'une saisie valide, dont on ne change qu'un champ.
function transfer(input: Partial<{ amount: string; toAccount: string; label: string }>) {
  return validate(transferSchema, { amount: "12,50", toAccount: "RA0123456789", label: "", ...input });
}

describe("transferSchema : montant", () => {
  it.each([
    ["12,50", 1250],
    ["12.5", 1250],
    ["0,01", 1],
    [" 1 000,00 ", 100_000],
    ["1 000,5", 100_050], // espace fine insécable collée depuis un montant formaté
    ["10000", 1_000_000],
  ])("accepte « %s » = %i centimes", (amount, cents) => {
    expect(transfer({ amount })).toEqual({ data: { amount: cents, toAccount: "RA0123456789", label: "" }, errors: null });
  });

  it.each(["", "   ", "0", "0,00", "-5", "12,345", "12,", ",50", "1e3", "douze", "12,50 €"])(
    "refuse « %s » (montant invalide)",
    (amount) => {
      expect(transfer({ amount }).errors).toEqual({ amount: "Montant invalide (ex. 12,50)." });
    },
  );

  it("plafonne à 10 000,00 € comme l'API (amount_cents ≤ 1 000 000)", () => {
    expect(transfer({ amount: "10 000,00" }).errors).toBeNull();
    expect(transfer({ amount: "10 000,01" }).errors).toEqual({ amount: "Montant maximum : 10 000,00 €." });
    expect(transfer({ amount: "250000" }).errors).toEqual({ amount: "Montant maximum : 10 000,00 €." });
  });
});

describe("transferSchema : compte bénéficiaire", () => {
  it("normalise la saisie (espaces retirés, majuscules) avant de vérifier le format", () => {
    expect(transfer({ toAccount: " ra 0123 4567 89 " }).data?.toAccount).toBe("RA0123456789");
  });

  it("exige un compte", () => {
    expect(transfer({ toAccount: "" }).errors).toEqual({ toAccount: "Compte bénéficiaire requis." });
    expect(transfer({ toAccount: "   " }).errors).toEqual({ toAccount: "Compte bénéficiaire requis." });
  });

  it.each(["RA012345678", "RA01234567890", "FR0123456789", "RA01234567AB", "0123456789", "R A0123456789X"])(
    "refuse « %s » (RA suivi de 10 chiffres)",
    (toAccount) => {
      expect(transfer({ toAccount }).errors).toEqual({ toAccount: "Format attendu : RA suivi de 10 chiffres." });
    },
  );
});

describe("transferSchema : libellé", () => {
  it("est facultatif", () => {
    expect(transfer({ label: "" }).errors).toBeNull();
  });

  it(`accepte ${LABEL_MAX} caractères et refuse au-delà`, () => {
    expect(LABEL_MAX).toBe(60); // même limite que label (max_length=60) dans payment-api
    expect(transfer({ label: "é".repeat(60) }).data?.label).toHaveLength(60);
    expect(transfer({ label: "é".repeat(61) }).errors).toEqual({ label: "Libellé limité à 60 caractères." });
  });

  it("retire les espaces autour avant de compter", () => {
    expect(transfer({ label: `  ${"a".repeat(60)}  ` }).data?.label).toBe("a".repeat(60));
    expect(transfer({ label: "  Resto du jeudi  " }).data?.label).toBe("Resto du jeudi");
  });
});

describe("validate", () => {
  it("renvoie le premier message de chaque champ en erreur, tous champs confondus", () => {
    expect(validate(transferSchema, { amount: "abc", toAccount: "", label: "x".repeat(61) }).errors).toEqual({
      amount: "Montant invalide (ex. 12,50).",
      toAccount: "Compte bénéficiaire requis.",
      label: "Libellé limité à 60 caractères.",
    });
  });
});

describe("loginSchema", () => {
  const password = crypto.randomUUID();

  it("exige un email et un mot de passe", () => {
    const { errors } = validate(loginSchema, { email: " ", password: password.slice(0, 0) });
    expect(Object.keys(errors ?? {})).toEqual(["email", "password"]);
    expect(errors?.email).toBe("Email requis.");
    expect(errors?.password).toBe("Mot de passe requis.");
  });

  it("nettoie l'email mais jamais le mot de passe", () => {
    expect(validate(loginSchema, { email: "  alice@exemple.fr ", password: ` ${password} ` }).data).toEqual({
      email: "alice@exemple.fr",
      password: ` ${password} `,
    });
  });

  it("borne les longueurs (email 254, mot de passe 128)", () => {
    expect(validate(loginSchema, { email: `${"a".repeat(250)}@exemple.fr`, password }).errors).toEqual({ email: "Email trop long." });
    const tooLong = validate(loginSchema, { email: "alice@exemple.fr", password: password.repeat(4) }).errors;
    expect(Object.keys(tooLong ?? {})).toEqual(["password"]);
    expect(tooLong?.password).toBe("128 caractères maximum.");
  });
});

describe("registerSchema", () => {
  const password = crypto.randomUUID();
  const valid = { fullName: "Alice Martin", email: "alice@exemple.fr", password };

  it("accepte une inscription valide et nettoie nom et email", () => {
    expect(validate(registerSchema, { ...valid, fullName: "  Alice Martin ", email: " alice@exemple.fr " }).data).toEqual(valid);
  });

  it("exige un nom complet de 2 à 80 caractères", () => {
    expect(validate(registerSchema, { ...valid, fullName: " A " }).errors).toEqual({ fullName: "Nom complet : 2 caractères minimum." });
    expect(validate(registerSchema, { ...valid, fullName: "A".repeat(81) }).errors).toEqual({
      fullName: "Nom complet : 80 caractères maximum.",
    });
  });

  it.each(["alice", "alice@", "@exemple.fr", "alice@exemple", "alice@exemple.f", "ali ce@exemple.fr", "a@b@exemple.fr"])(
    "refuse l'email « %s » (même motif que l'auth-service)",
    (email) => {
      expect(validate(registerSchema, { ...valid, email }).errors).toEqual({ email: "Adresse email invalide." });
    },
  );

  it("impose 10 à 128 caractères au mot de passe", () => {
    // Seul le champ du mot de passe est en erreur, avec le message attendu.
    const passwordError = (candidate: string) => {
      const { errors } = validate(registerSchema, { ...valid, password: candidate });
      expect(Object.keys(errors ?? {})).toEqual(errors ? ["password"] : []);
      return errors?.password ?? null;
    };
    expect(passwordError(password.slice(0, 9))).toBe("10 caractères minimum.");
    expect(passwordError(password.slice(0, 10))).toBeNull();
    expect(passwordError(password.repeat(4))).toBe("128 caractères maximum.");
  });
});
