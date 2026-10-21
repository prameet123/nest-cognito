import { Body, Controller, Get, Post, Req } from '@nestjs/common';
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
}
