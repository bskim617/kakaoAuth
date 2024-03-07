import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { AuthService } from '../auth.service';

// Basic 인증 방식은 HTTP 헤더에 사용자 이름과 비밀번호를 Base64 인코딩 형태로 넣어
// 서버에 전송하는 매우 간단한 인증 방식입니다.
// 이 방식은 HTTPS와 같은 안전한 연결에서 사용할 때만 적절합니다.
// 그러나 Basic 인증은 매 요청마다 사용자 이름과 비밀번호를 전송해야 하며,
// 인증 정보가 쉽게 노출될 수 있는 단점이 있습니다.

@Injectable()
export class UserBasicTokenGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 현재 HTTP 요청 객체를 가져온다.
    const req = context.switchToHttp().getRequest();

    // 요청 헤더에서 authorization 키를 사용해 인증 토큰을 가져옵니다.
    const rawToken = req.headers['authorization'];
    if (!rawToken) {
      throw new BadRequestException('토큰이 없습니다.');
    }

    // 토큰을 공백으로 나눔, 유효한 토큰은 "Basic ${token}" 형태
    const splitToken = rawToken.split(' ');
    if (splitToken.length !== 2 || splitToken[0] !== 'Basic') {
      throw new ForbiddenException('잘못된 토큰');
    }

    // base64로 인코딩된 토큰을 디코딩
    const token = splitToken[1];
    const decoded = Buffer.from(token, 'base64').toString('utf8');

    // 디코딩된 값을 ':'로 나누어 이메일과 패스워드(여기서는 사용 안함)를 분리합니다.
    const split = decoded.split(':');
    if (split.length !== 2) {
      throw new BadRequestException('잘못된 토큰입니다.');
    }

    // 분리한 이메일을 사용하여 사용자 인증을 시도
    const email = split[0];
    const member = await this.authService.jwtLogin({ email });

    // 인증된 사용자가 없으면 오류 발생
    if (!member) {
      throw new ForbiddenException('회원정보를 확인하세요.');
    }

    // 요청 객체에 인증된 사용자 정보를 추가, 이후 요청 처리 과정에서 사용
    req.user = member;
    // 모든 검증이 통과하면 true
    return true;
  }
}
