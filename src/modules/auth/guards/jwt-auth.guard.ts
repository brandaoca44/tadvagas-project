import { ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  handleRequest(err: any, user: any) {
    if (err || !user) {
      throw err || new UnauthorizedException('Usuário não autenticado');
    }
    return user;
  }

  getRequest(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();

    // extrai token do cookie
    const token = request.cookies?.access_token;

    if (token) {
      request.headers.authorization = `Bearer ${token}`;
    }

    return request;
  }
}