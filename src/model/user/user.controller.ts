import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from '../auth/auth.service';
import { UserService } from './user.service';
import { JwtAuthGuard } from '../auth/jwt/jwt.guard';

@Controller('user')
export class UserController {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UserService,
  ) {}

  //카카오 로그인/회원가입
  @Post('kakao/login')
  async login(@Body('code') code: string, @Res() res) {
    try {
      // 카카오로부터 액세스 토큰을 얻는 과정
      const accessToken = await this.authService.getToken(code);
      // 액세스 토큰을 사용하여 카카오로부터 사용자 정보를 얻는 과정
      const kakaoUserInfo = await this.authService.userInfo(accessToken);

      // 데이터베이스에서 이메일을 기준으로 기존 사용자를 찾거나 새 사용자 정보를 저장
      let user = await this.userService.findByEmail(
        kakaoUserInfo.kakao_account.email,
      );
      if (!user) {
        user = await this.userService.saveUserInfo({
          email: kakaoUserInfo.kakao_account.email,
          name: kakaoUserInfo.properties.nickname, // 카카오 응답 구조에 따름
          profileImage: kakaoUserInfo.kakao_account.profile.profile_image_url,
          hpNo: kakaoUserInfo.kakao_account.phone_number,
          ageRange: kakaoUserInfo.kakao_account.age_range,
          birthyear: kakaoUserInfo.kakao_account.birthyear,
          birthday: kakaoUserInfo.kakao_account.birthday,
          gender: kakaoUserInfo.kakao_account.gender,
        });
      }

      // 로그인 성공 응답 반환
      return res.status(HttpStatus.OK).json({
        message: '로그인 성공',
        user,
      });
    } catch (error) {
      // 에러 처리 및 에러 응답 반환
      console.error('로그인 처리 중 오류 발생:', error);
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: '로그인 처리 중 오류 발생',
      });
    }
  }

  //카카오 로그아웃
  @Get('kakao/logout')
  async logout() {
    return this.authService.kakaologout();
  }

  //user정보 가지고 오기
  @Get('userinfo')
  @UseGuards(JwtAuthGuard)
  async userInfo(@Req() req) {
    const user = req.user.email;
    return this.userService.findByEmail(user);
  }
}
