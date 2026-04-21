import { ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtRefreshGuard extends AuthGuard('jwt-refresh') {
  handleRequest(err: any, user: any) {
    if (err || !user) {
      throw err || new UnauthorizedException('Refresh token inválido');
    }
    return user;
  }

  getRequest(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();

    const refreshToken = request.cookies?.refresh_token;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token não encontrado');
    }

    // injeta no header para o passport validar
    request.headers.authorization = `Bearer ${refreshToken}`;

    // salva no request para o service usar depois
    request.refreshToken = refreshToken;

    return request;
  }
}