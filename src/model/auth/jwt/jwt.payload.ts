import { Types } from 'mongoose';

export type Payload = {
  email: string;
  sub: Types.ObjectId;
  type?: 'access' | 'refresh';
};
