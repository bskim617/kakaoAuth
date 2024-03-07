import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UserService } from 'src/model/user/user.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly userService: UserService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
      ignoreExpiration: false,
    });
  }

  async validate(payload: any) {
    try {
      const user = await this.userService.findByInfoUser(payload.sub);
      if (user) {
        return user;
      } else {
        throw new Error('유저를 찾을 수 없습니다.');
      }
    } catch (error) {
      console.error('Error in JWT Strategy validate:', error.message);
      throw new UnauthorizedException('접근 오류');
    }
  }
}
