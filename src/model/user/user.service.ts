import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { User } from './schema/user.schema';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
  ) {}

  // jwt토큰 strategy에서 user가 있는지 없는지 찾는다.
  async findByInfoUser(id: Types.ObjectId): Promise<User> {
    console.log('userID: ', id);
    const user = await this.userModel.findById(id);
    if (!user) {
      throw new Error('사용자를 찾을 수 없습니다.');
    }
    return user;
  }

  async findByEmail(email: string): Promise<User | null> {
    return await this.userModel.findOne({ email }).exec();
  }

  async saveUserInfo(userData: any): Promise<User> {
    const user = await this.userModel.findOne({ email: userData.email }).exec();
    if (!user) {
      const user = new this.userModel(userData);
      await user.save();
    }
    return user;
  }
}
