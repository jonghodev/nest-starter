import {
  Body,
  Controller,
  Delete,
  HttpCode,
  Post,
  Put,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { EmailSignupDto } from './dto/email-signup.dto';
import { SendVerificationCodeDto } from './dto/send-verificaion-code.dto';
import { VerifyCodeDto } from './dto/verify-code.dto';
import { User } from '../user/schemas/user.schema';
import { AuthService } from './auth.service';
import { ApiResponse } from '../util/http';
import { LocalAuthGuard } from './guard/local-auth.guard';
import { ReqUser } from '../decorator/user.decorator';
import { FindPasswordDto } from './dto/find-password.dto';
import { SnsSignupDto } from './dto/sns-signup-dto';
import { SnsLoginDto } from './dto/sns-login-dto';
import { VerificationType } from './schemas/verification.schema';
import { JwtAuthGuard } from './guard/jwt-auth.guard';

@Controller('/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * Login
   */

  @HttpCode(200)
  @UseGuards(LocalAuthGuard)
  @Post('/tokens/email')
  async loginWithEmail(@ReqUser() user: User): Promise<ApiResponse> {
    const accessToken = this.authService.login(user);
    return ApiResponse.create('email login success', { user, accessToken });
  }

  @HttpCode(200)
  @Post('/tokens/google')
  async googleLogin(@Body() snsLoginDto: SnsLoginDto): Promise<ApiResponse> {
    const { user, accessToken } = await this.authService.googleLogin(
      snsLoginDto,
    );
    return ApiResponse.create('google login success', {
      user,
      accessToken,
    });
  }

  @HttpCode(200)
  @Post('/tokens/facebook')
  async facebookLogin(@Body() snsLoginDto: SnsLoginDto): Promise<ApiResponse> {
    const { user, accessToken } = await this.authService.facebookLogin(
      snsLoginDto,
    );
    return ApiResponse.create('facebook login success', {
      user,
      accessToken,
    });
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(200)
  @Delete('/tokens')
  async logout(@Req() req: Request): Promise<ApiResponse> {
    await this.authService.logout(req);
    return ApiResponse.create('logout success');
  }

  /**
   * Signup
   */

  @HttpCode(201)
  @Post('/users/email')
  async emailSignup(
    @Body() emailSignupDto: EmailSignupDto,
  ): Promise<ApiResponse> {
    const savedUser = await this.authService.emailSignup(emailSignupDto);
    return ApiResponse.create('email signup success', savedUser);
  }

  @HttpCode(201)
  @Post('/users/google')
  async googleSignup(@Body() snsSignupDto: SnsSignupDto): Promise<ApiResponse> {
    const savedUser = await this.authService.googleSignup(snsSignupDto);
    return ApiResponse.create('google signup success', savedUser);
  }

  @HttpCode(201)
  @Post('/users/facebook')
  async facebookSignup(
    @Body() snsSignupDto: SnsSignupDto,
  ): Promise<ApiResponse> {
    const savedUser = await this.authService.facebookSignup(snsSignupDto);
    return ApiResponse.create('facebook signup success', savedUser);
  }

  /**
   * Find password
   */

  @HttpCode(200)
  @Put('/find-password')
  async findPassword(@Body() findPasswordDto: FindPasswordDto): Promise<any> {
    await this.authService.findPassword(findPasswordDto);
    return ApiResponse.create('find password success');
  }

  /**
   * Verifications
   */

  @HttpCode(200)
  @Post('/verifications/signup/send')
  async sendVerificationCodeForSignup(
    @Body() sendVerificationCodeDto: SendVerificationCodeDto,
  ): Promise<ApiResponse> {
    await this.authService.sendVerificationCodeForSignup(
      sendVerificationCodeDto.email,
    );
    return ApiResponse.create('signup verification code send success');
  }

  @HttpCode(200)
  @Post('/verifications/signup/verify')
  async verifyCodeForSignup(
    @Body() verifyCodeDto: VerifyCodeDto,
  ): Promise<ApiResponse> {
    await this.authService.verifyEmail(
      verifyCodeDto.email,
      verifyCodeDto.verificationCode,
      VerificationType.SIGNUP,
    );
    return ApiResponse.create('verify success');
  }

  @HttpCode(200)
  @Post('/verifications/find-password/send')
  async sendVerificationCodeForFindPassword(
    @Body() sendVerificationCodeDto: SendVerificationCodeDto,
  ): Promise<ApiResponse> {
    await this.authService.sendVerificationCodeForFindPassword(
      sendVerificationCodeDto.email,
    );
    return ApiResponse.create('find password verification code send success');
  }

  @HttpCode(200)
  @Post('/verifications/find-password/verify')
  async verifyCodeForFindPassword(
    @Body() verifyCodeDto: VerifyCodeDto,
  ): Promise<ApiResponse> {
    await this.authService.verifyEmail(
      verifyCodeDto.email,
      verifyCodeDto.verificationCode,
      VerificationType.FIND_PASSWORD,
    );
    return ApiResponse.create('verify success');
  }

  @HttpCode(200)
  @Post('/verifications/change-email/send')
  async sendVerificationCodeForChangeEmail(
    @Body() sendVerificationCodeDto: SendVerificationCodeDto,
  ): Promise<ApiResponse> {
    await this.authService.sendVerificationCodeForChangeEmail(
      sendVerificationCodeDto.email,
    );
    return ApiResponse.create('change email verification code send success');
  }

  @HttpCode(200)
  @Post('/verification/change-email/verify')
  async verifyCodeForChangeEmail(
    @Body() verifyCodeDto: VerifyCodeDto,
  ): Promise<ApiResponse> {
    await this.authService.verifyEmail(
      verifyCodeDto.email,
      verifyCodeDto.verificationCode,
      VerificationType.CHANGE_EMAIL,
    );
    return ApiResponse.create('verify success');
  }
}
