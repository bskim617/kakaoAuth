import * as bcrypt from 'bcrypt';
export const toHash = (password: string) => {
  return bcrypt.hash(password, 10);
};

export const compareWithHash = async (value, hashedValue) => {
  return await bcrypt.compare(value, hashedValue);
};
