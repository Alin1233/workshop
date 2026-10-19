// Schémas de validation des formulaires (Zod), alignés sur les contraintes des API auth et payments.
import { z } from "zod";
import { parseEuros } from "./api";

export const LABEL_MAX = 60;
export const FULL_NAME_MAX = 80;
export const PASSWORD_MIN = 10;
export const PASSWORD_MAX = 128;
export const EMAIL_MAX = 254;
const AMOUNT_MAX_CENTS = 1_000_000;

// Même motif que EMAIL_PATTERN côté auth-service.
const EMAIL_PATTERN = /^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$/;

export const transferSchema = z.object({
  amount: z
    .string()
    .transform((value, ctx) => {
      const cents = parseEuros(value);
      if (cents === null) ctx.addIssue({ code: "custom", message: "Montant invalide (ex. 12,50)." });
      else if (cents > AMOUNT_MAX_CENTS) ctx.addIssue({ code: "custom", message: "Montant maximum : 10 000,00 €." });
      return cents ?? 0;
    }),
  toAccount: z
    .string()
    .transform((value) => value.replace(/\s/g, "").toUpperCase())
    .pipe(z.string().min(1, "Compte bénéficiaire requis.").regex(/^RA\d{10}$/, "Format attendu : RA suivi de 10 chiffres.")),
  label: z.string().trim().max(LABEL_MAX, `Libellé limité à ${LABEL_MAX} caractères.`),
});

export const loginSchema = z.object({
  email: z.string().trim().min(1, "Email requis.").max(EMAIL_MAX, "Email trop long."),
  password: z.string().min(1, "Mot de passe requis.").max(PASSWORD_MAX, `${PASSWORD_MAX} caractères maximum.`),
});

export const registerSchema = z.object({
  fullName: z
    .string()
    .trim()
    .min(2, "Nom complet : 2 caractères minimum.")
    .max(FULL_NAME_MAX, `Nom complet : ${FULL_NAME_MAX} caractères maximum.`),
  email: z.string().trim().max(EMAIL_MAX, "Email trop long.").regex(EMAIL_PATTERN, "Adresse email invalide."),
  password: z
    .string()
    .min(PASSWORD_MIN, `${PASSWORD_MIN} caractères minimum.`)
    .max(PASSWORD_MAX, `${PASSWORD_MAX} caractères maximum.`),
});

export type FieldErrors<T> = Partial<Record<keyof T, string>>;

// Cette méthode permet de valider une saisie avec un schéma Zod et de renvoyer soit les données nettoyées,
// soit le premier message d'erreur de chaque champ, à afficher sous le champ concerné.
export function validate<S extends z.ZodObject>(
  schema: S,
  input: z.input<S>,
): { data: z.output<S>; errors: null } | { data: null; errors: FieldErrors<z.input<S>> } {
  const result = schema.safeParse(input);
  if (result.success) return { data: result.data, errors: null };
  const errors: FieldErrors<z.input<S>> = {};
  for (const issue of result.error.issues) {
    const field = issue.path[0] as keyof z.input<S>;
    errors[field] ??= issue.message;
  }
  return { data: null, errors };
}
