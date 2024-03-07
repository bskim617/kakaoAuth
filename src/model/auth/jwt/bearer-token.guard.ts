import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from '../auth.service';
import { UserService } from 'src/model/user/user.service';

@Injectable()
export class UserBearerTokenGuard implements CanActivate {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UserService,
  ) {}
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

    // 토큰이 블랙리스트에 있는지 검사, 사용 금지된 토큰일 경우 예외 발생
    if (this.authService.isTokenBlacklisted(token)) {
      throw new UnauthorizedException('이 토큰은 사용할 수 없습니다.');
    }

    let payload;
    try {
      // 토큰을 검증하고 페이로드를 추출
      payload = this.authService.verifyToken(token);
    } catch (error) {
      throw new UnauthorizedException('잘못된 토큰입니다.');
    }

    // 페이로드에 sub(주체) 필드가 없는 경우 예외를 발생
    if (!payload.sub) {
      throw new UnauthorizedException('잘못된 토큰입니다.');
    }

    // 페이로드에서 이메일을 추출하여 사용자를 찾습니다.
    const findUser = await this.userService.findByEmail(payload.email);
    req.user = findUser;
    req.token = token;
    req.tokenType = payload.type;

    return true;
  }
}

@Injectable()
export class UserAccessTokenGuard extends UserBearerTokenGuard {
  // UserBearerTokenGuard의 canActivate 메서드를 확장
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 부모 클래스의 canActivate를 호출하여 기본 검증 로직을 수행
    await super.canActivate(context);
    const req = context.switchToHttp().getRequest();
    // 토큰 유형이 'access'가 아니면 예외를 발생
    if (req.tokenType !== 'access') {
      throw new UnauthorizedException('Access토큰이 아닙니다.');
    }
    return true;
  }
}

@Injectable()
export class UserRefreshTokenGuard extends UserBearerTokenGuard {
  // UserBearerTokenGuard의 canActivate 메소드를 확장합니다.
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 부모 클래스의 canActivate를 호출하여 기본 검증 로직을 수행합니다.
    await super.canActivate(context);
    const req = context.switchToHttp().getRequest();
    // 토큰 유형이 'refresh'가 아니면 예외를 발생시킵니다.
    if (req.tokenType !== 'refresh') {
      throw new UnauthorizedException('Refresh Token이 아닙니다.');
    }
    return true;
  }
}
