import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UserRole } from '@prisma/client';

import { PrismaService } from '../../prisma/prisma.service';
import { LoginDto } from './dto/login.dto';
import { RegisterCandidateDto } from './dto/register-candidate.dto';
import { RegisterCompanyDto } from './dto/register-company.dto';

type SafeUser<T> = Omit<T, 'passwordHash' | 'refreshTokenHash'>;

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  async registerCandidate(dto: RegisterCandidateDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existingUser) {
      throw new BadRequestException('Email já está em uso.');
    }

    const passwordHash = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.$transaction(async (tx) => {
      const createdUser = await tx.user.create({
        data: {
          email: dto.email,
          passwordHash,
          role: UserRole.CANDIDATE,
        },
      });

      await tx.candidateProfile.create({
        data: {
          userId: createdUser.id,
          fullName: dto.fullName,
        },
      });

      return createdUser;
    });

    const tokens = await this.generateTokens(user.id, user.email, user.role);

    return {
      user: this.sanitizeUser(user),
      ...tokens,
    };
  }

  async registerCompany(dto: RegisterCompanyDto) {
    const existingUser = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existingUser) {
      throw new BadRequestException('Email já está em uso.');
    }

    const passwordHash = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.$transaction(async (tx) => {
      const createdUser = await tx.user.create({
        data: {
          email: dto.email,
          passwordHash,
          role: UserRole.COMPANY,
        },
      });

      await tx.companyProfile.create({
        data: {
          userId: createdUser.id,
          name: dto.companyName,
          corporateEmail: dto.email,
        },
      });

      return createdUser;
    });

    const tokens = await this.generateTokens(user.id, user.email, user.role);

    return {
      user: this.sanitizeUser(user),
      ...tokens,
    };
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new UnauthorizedException('Credenciais inválidas.');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Conta desativada.');
    }

    const passwordValid = await bcrypt.compare(dto.password, user.passwordHash);

    if (!passwordValid) {
      throw new UnauthorizedException('Credenciais inválidas.');
    }

    const tokens = await this.generateTokens(user.id, user.email, user.role);

    return {
      user: this.sanitizeUser(user),
      ...tokens,
    };
  }

  async refresh(userId: string, refreshToken: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !user.refreshTokenHash) {
      throw new UnauthorizedException('Acesso negado.');
    }

    if (!user.isActive) {
      throw new UnauthorizedException('Conta desativada.');
    }

    const isMatch = await bcrypt.compare(refreshToken, user.refreshTokenHash);

    if (!isMatch) {
      throw new UnauthorizedException('Refresh token inválido.');
    }

    return this.generateTokens(user.id, user.email, user.role);
  }

  async logout(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshTokenHash: null },
    });
  }

  async me(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        candidateProfile: true,
        companyProfile: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('Usuário não encontrado.');
    }

    return this.sanitizeUser(user);
  }

  private async generateTokens(
  userId: string,
  email: string,
  role: UserRole,
) {
  const payload = { sub: userId, email, role };

  const accessToken = this.jwt.sign(payload, {
    secret: this.config.get<string>('JWT_SECRET'),
    expiresIn: this.config.get<string>('JWT_EXPIRES_IN'),
  });

  const refreshToken = this.jwt.sign(payload, {
    secret: this.config.get<string>('JWT_REFRESH_SECRET'),
    expiresIn: this.config.get<string>('JWT_REFRESH_EXPIRES_IN'),
  });

  const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

  await this.prisma.user.update({
    where: { id: userId },
    data: { refreshTokenHash },
  });

  return {
    accessToken,
    refreshToken,
  };
}

private sanitizeUser<T extends Record<string, any>>(user: T) {
  const { passwordHash, refreshTokenHash, ...safeUser } = user;
  return safeUser;
}
}