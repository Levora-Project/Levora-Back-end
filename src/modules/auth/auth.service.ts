import {
  Injectable,
  UnauthorizedException,
  ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import { InjectPinoLogger, PinoLogger } from 'nestjs-pino';
import { UsersService } from '@/modules/users/users.service';
import {
  UsersRepository,
  UserRolesRepository,
} from '@/modules/users/repositories';
import { LoginDto, RegisterDto, RefreshTokenDto, UserResponseDto } from './dto';

export interface JwtPayload {
  sub: string;
  email: string;
  role: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class AuthService {
  constructor(
    @InjectPinoLogger(AuthService.name)
    private readonly logger: PinoLogger,
    private readonly usersService: UsersService,
    private readonly usersRepo: UsersRepository,
    private readonly userRolesRepo: UserRolesRepository,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  // ── Register ─────────────────────────────────
  async register(dto: RegisterDto): Promise<UserResponseDto> {
    const existing = await this.usersService.findByEmail(dto.email);
    if (existing) {
      this.logger.warn(
        `Registration failed: email ${dto.email} already exists`,
      );
      throw new ConflictException('Email already registered');
    }

    const hashedPassword = await bcrypt.hash(dto.password, 12);

    const user = await this.usersService.createUser({
      email: dto.email,
      password: hashedPassword,
      firstName: dto.firstName,
      lastName: dto.lastName,
    });

    this.logger.info(`User registered successfully: ${user.email}`);

    return this.formatUserResponse(user);
  }

  // ── Login ────────────────────────────────────
  async login(dto: LoginDto) {
    const user = await this.usersRepo.findUniqueRaw({
      where: { email: dto.email },
      select: {
        id: true,
        email: true,
        password: true,
        firstName: true,
        lastName: true,
        isEmailVerified: true,
        isActive: true,
        lastLoginAt: true,
        createdAt: true,
        userProfile: {
          select: {
            fullName: true,
            completionPct: true,
            isDraft: true,
          },
        },
      },
    });

    if (!user || !user.isActive) {
      this.logger.warn(
        `Failed login attempt: ${dto.email} (user not found or inactive)`,
      );
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.password) {
      this.logger.warn(
        `Failed login attempt: ${dto.email} (SSO-only account, no password)`,
      );
      throw new UnauthorizedException(
        'This account uses SSO login. Please sign in with your provider.',
      );
    }

    const passwordValid = await bcrypt.compare(dto.password, user.password);
    if (!passwordValid) {
      this.logger.warn(`Failed login attempt: ${dto.email} (wrong password)`);
      throw new UnauthorizedException('Invalid credentials');
    }

    await this.usersService.updateLastLogin(user.id);
    const role = await this.userRolesRepo.getCurrentRoleName(user.id);

    const tokens = await this.generateTokens(user.id, user.email, role);

    const userOutput: UserResponseDto = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      isEmailVerified: user.isEmailVerified,
      isActive: user.isActive,
      lastLoginAt: new Date(),
      createdAt: user.createdAt,
      userProfile: user.userProfile,
      roles: [role],
    };

    this.logger.info(`User logged in: ${user.email}`);

    return {
      ...tokens,
      user: userOutput,
    };
  }

  // ── Refresh Token ────────────────────────────
  async refreshToken(dto: RefreshTokenDto | string) {
    const token = typeof dto === 'string' ? dto : dto.refreshToken;
    if (!token) {
      throw new UnauthorizedException('Refresh token is required');
    }
    try {
      const payload = await this.jwt.verifyAsync<JwtPayload>(token);
      const user = await this.usersService.findById(payload.sub);

      if (!user || !user.isActive) {
        throw new UnauthorizedException('Account is deactivated');
      }

      const role = await this.userRolesRepo.getCurrentRoleName(user.id);
      const tokens = await this.generateTokens(user.id, user.email, role);

      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  // Alias for backward compatibility
  async refresh(token: string) {
    return this.refreshToken(token);
  }

  // ── Validate JWT payload (used by guard) ──────
  async validateUser(payload: JwtPayload) {
    const user = await this.usersService.findById(payload.sub);

    if (!user || !user.isActive) {
      throw new UnauthorizedException('User not found or deactivated');
    }

    const role = await this.userRolesRepo.getCurrentRoleName(user.id);
    return { ...user, role };
  }

  // ── Get Profile (GET /auth/me) ────────────────
  async getProfile(userId: string): Promise<UserResponseDto> {
    const user = await this.usersService.getUserWithProfile(userId);
    return this.formatUserResponse(user);
  }

  async getMe(userId: string): Promise<UserResponseDto> {
    return this.getProfile(userId);
  }

  // ── Helpers ──────────────────────────────────
  private formatUserResponse(user: Record<string, unknown>): UserResponseDto {
    let roles: string[] = ['user'];
    if (Array.isArray(user.userRoles)) {
      roles = user.userRoles.map(
        (ur) => (ur as { roles?: { name?: string } })?.roles?.name ?? 'user',
      );
    } else if (Array.isArray(user.roles)) {
      roles = user.roles as string[];
    }

    return {
      id: user.id as string,
      email: user.email as string,
      firstName: (user.firstName as string) ?? null,
      lastName: (user.lastName as string) ?? null,
      isEmailVerified: (user.isEmailVerified as boolean) ?? false,
      isActive: (user.isActive as boolean) ?? true,
      lastLoginAt: (user.lastLoginAt as Date) ?? null,
      createdAt: user.createdAt as Date,
      userProfile: (user.userProfile as UserResponseDto['userProfile']) ?? null,
      roles,
    };
  }

  private async generateTokens(
    userId: string,
    email: string,
    role: string,
  ): Promise<AuthTokens> {
    const payload: JwtPayload = { sub: userId, email, role };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwt.signAsync(payload, {
        expiresIn: this.config.get<string>(
          'security.JWT_ACCESS_EXPIRES',
          '15m',
        ) as `${number}${'s' | 'm' | 'h' | 'd'}`,
      }),
      this.jwt.signAsync(payload, {
        expiresIn: this.config.get<string>(
          'security.JWT_REFRESH_EXPIRES',
          '7d',
        ) as `${number}${'s' | 'm' | 'h' | 'd'}`,
      }),
    ]);

    return { accessToken, refreshToken };
  }
}
