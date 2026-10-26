import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { UseGuards } from '@nestjs/common';
import { CognitoAuthGuard } from './cognito-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signUp(@Body() body: { email: string; password: string }) {
    return this.authService.signUp(body.email, body.password);
  }

  @Post('confirm-signup')
  confirmSignUp(@Body() body: { email: string; confirmationCode: string }) {
    return this.authService.confirmSignUp(body.email, body.confirmationCode);
  }

  @Post('login')
  login(@Body() body: { email: string; password: string }) {
    return this.authService.login(body.email, body.password);
  }
  @Get('profile')
  @UseGuards(CognitoAuthGuard)
  getProfile(@Req() request: any) {
    return {
      userSub: request.user.sub,
      username: request.user.username,
      message: 'Access token verified successfully',
    };
  }

  @Get('sso/callback')
  ssoCallback(@Query('code') code?: string) {
    if (!code) {
      throw new BadRequestException('Missing authorization code');
    }

    // Temporary testing only: do not exchange the code here.
    return {
      message: 'Authorization code received',
      codeReceived: true,
      nextStep: 'Submit the code to POST /auth/sso/token',
    };
  }

  @Post('sso/token')
  @HttpCode(HttpStatus.OK)
  async exchangeSsoToken(@Body() body: { code?: string }) {
    if (!body.code || typeof body.code !== 'string') {
      throw new BadRequestException('Authorization code is required');
    }

    return this.authService.exchangeSsoCode(body.code);
  }
}
