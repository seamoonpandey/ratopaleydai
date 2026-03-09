import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { UserEntity } from './entities/user.entity';
import { JwtPayload } from './strategies/jwt.strategy';

export interface OAuthProfile {
  provider: string;
  providerId: string;
  email: string;
  name?: string;
  avatar?: string;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepo: Repository<UserEntity>,
    private readonly jwtService: JwtService,
  ) {}

  /**
   * Find or create user from OAuth profile
   */
  async validateOAuthUser(profile: OAuthProfile): Promise<UserEntity> {
    const { provider, providerId, email, name, avatar } = profile;

    // Try to find existing user
    let user = await this.userRepo.findOne({
      where: { provider, providerId },
    });

    if (user) {
      // Update user info if changed
      user.email = email;
      user.name = name || user.name;
      user.avatar = avatar || user.avatar;
      user = await this.userRepo.save(user);
      this.logger.log(`User ${user.id} logged in via ${provider}`);
    } else {
      // Create new user
      user = this.userRepo.create({
        provider,
        providerId,
        email,
        name,
        avatar,
        isActive: true,
      });
      user = await this.userRepo.save(user);
      this.logger.log(`New user ${user.id} registered via ${provider}`);
    }

    return user;
  }

  /**
   * Generate JWT access token for user
   */
  generateAccessToken(user: UserEntity): string {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      name: user.name,
    };
    return this.jwtService.sign(payload);
  }

  /**
   * Find user by ID
   */
  async findUserById(id: string): Promise<UserEntity | null> {
    return this.userRepo.findOne({ where: { id } });
  }

  /**
   * Generate or retrieve API key for a user
   */
  async generateApiKey(userId: string): Promise<string> {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new Error('User not found');

    if (!user.apiKey) {
      // Generate a random API key
      const apiKey = `rs_${Buffer.from(Math.random().toString()).toString('base64').slice(0, 32)}`;
      user.apiKey = apiKey;
      await this.userRepo.save(user);
    }

    return user.apiKey;
  }
}
