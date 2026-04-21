import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Response } from 'express';

import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterCandidateDto } from './dto/register-candidate.dto';
import { RegisterCompanyDto } from './dto/register-company.dto';
import {
  AuthenticatedUser,
  CurrentUser,
} from './decorators/current-user.decorator';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register/candidate')
  @HttpCode(HttpStatus.CREATED)
  async registerCandidate(
    @Body() dto: RegisterCandidateDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.registerCandidate(dto);

    this.setAuthCookies(res, result.accessToken, result.refreshToken);

    return {
      message: 'Candidato cadastrado com sucesso.',
      user: result.user,
    };
  }

  @Post('register/company')
  @HttpCode(HttpStatus.CREATED)
  async registerCompany(
    @Body() dto: RegisterCompanyDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.registerCompany(dto);

    this.setAuthCookies(res, result.accessToken, result.refreshToken);

    return {
      message: 'Empresa cadastrada com sucesso.',
      user: result.user,
    };
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.login(dto);

    this.setAuthCookies(res, result.accessToken, result.refreshToken);

    return {
      message: 'Login realizado com sucesso.',
      user: result.user,
    };
  }

  @Post('refresh')
@UseGuards(JwtRefreshGuard)
@HttpCode(HttpStatus.OK)
async refresh(
  @CurrentUser() user: AuthenticatedUser,
  @Res({ passthrough: true }) res: Response,
) {
  const result = await this.authService.refresh(
    user.sub,
    user.refreshToken as string,
  );

  this.setAuthCookies(res, result.accessToken, result.refreshToken);

  return {
    message: 'Sessão renovada com sucesso.',
  };
}

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(
    @CurrentUser() user: AuthenticatedUser,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.logout(user.sub);
    this.clearAuthCookies(res);

    return {
      message: 'Logout realizado com sucesso.',
    };
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async me(@CurrentUser() user: AuthenticatedUser) {
    return this.authService.me(user.sub);
  }

  private setAuthCookies(
    res: Response,
    accessToken: string,
    refreshToken: string,
  ): void {
    const isProduction = process.env.NODE_ENV === 'production';

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: 15 * 60 * 1000,
      path: '/',
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/',
    });
  }

  private clearAuthCookies(res: Response): void {
    const isProduction = process.env.NODE_ENV === 'production';

    res.clearCookie('access_token', {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      path: '/',
    });

    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      path: '/',
    });
  }
}