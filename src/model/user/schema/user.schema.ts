import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true, collection: 'kakao_users' })
export class User extends Document {
  @Prop()
  name: string;

  @Prop()
  email: string;

  @Prop()
  nickname: string;

  @Prop()
  profileImage: string;

  @Prop()
  hpNo: string;

  @Prop()
  ageRange: string;

  @Prop()
  birthyear: string;

  @Prop()
  birthday: string;

  @Prop()
  gender: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
