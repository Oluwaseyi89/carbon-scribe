export const REGISTER_PASSWORD_MIN_LENGTH = 8;

export const REGISTER_PASSWORD_PATTERN =
  /((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/;

export const REGISTER_PASSWORD_ERROR =
  'Password must contain at least 8 characters, including uppercase, lowercase, and a number or special character';

export function validateRegisterPassword(password: string): string | null {
  if (password.length < REGISTER_PASSWORD_MIN_LENGTH) {
    return `Password must be at least ${REGISTER_PASSWORD_MIN_LENGTH} characters long`;
  }

  if (!REGISTER_PASSWORD_PATTERN.test(password)) {
    return REGISTER_PASSWORD_ERROR;
  }

  return null;
}