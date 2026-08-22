import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { IS_PUBLIC_KEY } from '@common/decorators';
import { AuthService, JwtPayload } from '@/modules/auth/auth.service';

/**
 * Combined auth guard that supports (in priority order):
 * 1. JWT in httpOnly cookie `accessToken` (browser / frontend)
 * 2. JWT Bearer token in Authorization header (mobile / Swagger)
 * 3. @Public() decorator to bypass auth
 *
 * Attaches `req.user`.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly jwt: JwtService,
    private readonly authService: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 1. Check @Public()
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    const request = context
      .switchToHttp()
      .getRequest<Record<string, unknown>>();

    // 2. Try JWT from httpOnly cookie (browser / frontend)
    const cookies = request.cookies as Record<string, string> | undefined;
    const cookieToken = cookies?.['accessToken'];
    if (cookieToken) {
      return this.validateJwt(request, cookieToken);
    }

    // 3. Try JWT Bearer header (mobile / Swagger)
    const headers = request.headers as Record<string, string | undefined>;
    const authHeader = headers?.['authorization'] || headers?.['Authorization'];
    if (
      authHeader &&
      typeof authHeader === 'string' &&
      authHeader.startsWith('Bearer ')
    ) {
      return this.validateJwt(request, authHeader.slice(7));
    }

    throw new UnauthorizedException(
      'Missing authentication: provide a cookie or Bearer token',
    );
  }

  private async validateJwt(
    request: Record<string, unknown>,
    token: string,
  ): Promise<boolean> {
    try {
      const payload = await this.jwt.verifyAsync<JwtPayload>(token);
      request.user = await this.authService.validateUser(payload);
      return true;
    } catch {
      throw new UnauthorizedException('Invalid or expired access token');
    }
  }
}
