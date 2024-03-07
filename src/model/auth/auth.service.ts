import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Payload } from './jwt/jwt.payload';

@Injectable()
export class AuthService {
  constructor(private readonly jwtService: JwtService) {}

  // 블랙리스트에 추가된 토큰을 저장하는 배열
  private blacklistedTokens: string[] = [];

  // 블랙리스트 확인: 토큰이 블랙리스트에 있는지 확인
  isTokenBlacklisted(token: string): boolean {
    return this.blacklistedTokens.includes(token);
  }

  // 토큰 검증: 주어진 토큰이 유효한지 검증하고 페이로드를 반환
  verifyToken(token: string): Payload {
    return this.jwtService.verify(token) as Payload;
  }

  // 토큰 디코드: 주어진 토큰을 디코드
  decodedToken(token: string) {
    return this.jwtService.decode(token);
  }

  // 토큰 서명: 주어진 페이로드를 기바능로 토큰을 생성
  signToken(payload: Payload, isRefreshToken: boolean): string {
    const tokenPayload = {
      email: payload.email,
      sub: payload.sub,
      type: isRefreshToken ? 'refresh' : 'access',
    };

    // 리프레시 토큰은 14일, 액세스 토큰은 1시간 유효
    return this.jwtService.sign(tokenPayload, {
      expiresIn: isRefreshToken ? '14d' : '1h',
    });
  }

  // 엑세스 토큰 생성: 리프레시 토큰을 기반으로 새로운 엑세스 토큰을 생성
  async rotateAccessToken(refreshToken: string): Promise<string> {
    const decoded = this.jwtService.verify(refreshToken);

    // false는 액세스 토큰으로 표시합니다.
    return this.signToken({ email: decoded.email, sub: decoded.sub }, false);
  }

  // jwt 토큰 발급: 사용자 인증 시 애게스 토큰과 리프레시 토큰 생성
  async getjwtTokens(payload: Payload) {
    return {
      accessToken: this.signToken(payload, false),
      refreshToken: this.signToken(payload, true),
    };
  }

  // jwt 로그인: 사용자 정보를 기반으로 JWT 토큰을 발급
  async jwtLogin(user: any) {
    const payload = {
      email: user.email,
      sub: (user as any)._id,
    };
    const token = await this.getjwtTokens(payload);

    return {
      accessToken: token.accessToken,
      refreshToken: token.refreshToken,
      user: user.email,
    };
  }

  // 카카오 로그인
  // 인가코드(보통 클라이언트 측에서 해결) -> 토큰 발급 -> 회원 정보 -> 로그인 완료

  // 카카오 로그아웃
}
