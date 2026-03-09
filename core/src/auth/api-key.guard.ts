import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Request } from 'express';
import { UserEntity } from './entities/user.entity';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly config: ConfigService,
    private readonly jwtService: JwtService,
    @InjectRepository(UserEntity)
    private readonly userRepo: Repository<UserEntity>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();

    // health endpoint is always public
    if (req.path === '/health') return true;

    // Check for JWT token first (Bearer token)
    const authHeader = req.headers['authorization'];
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      try {
        const payload = this.jwtService.verify(token, {
          secret: this.config.get<string>('JWT_SECRET') || 'dev-secret-change-in-production',
        });
        // Attach user info to request
        (req as any).user = { userId: payload.sub, email: payload.email, name: payload.name };
        return true;
      } catch (err) {
        // Invalid JWT, continue to check other auth methods
      }
    }

    // Check for user-specific API key
    const apiKey = req.headers['x-api-key'] as string;
    if (apiKey) {
      // Check if it's a user's API key
      const user = await this.userRepo.findOne({ where: { apiKey, isActive: true } });
      if (user) {
        (req as any).user = { userId: user.id, email: user.email, name: user.name };
        return true;
      }

      // Check if it's the global API key (for backwards compatibility)
      const globalKey = this.config.get<string>('API_KEY_SECRET');
      if (globalKey && apiKey === globalKey) {
        return true;
      }
    }

    // If no API key is configured, allow access in dev mode
    const expected = this.config.get<string>('API_KEY_SECRET');
    if (!expected) return true;

    throw new UnauthorizedException('invalid or missing authentication');
  }
}
