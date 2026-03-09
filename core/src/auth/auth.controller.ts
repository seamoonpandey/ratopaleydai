import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { GithubAuthGuard } from './guards/github-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import type { UserEntity } from './entities/user.entity';
import { ConfigService } from '@nestjs/config';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
  ) {}

  /**
   * Initiate Google OAuth login
   */
  @Get('google')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({ summary: 'Initiate Google OAuth login' })
  async googleAuth() {
    // Guard redirects to Google
  }

  /**
   * Google OAuth callback
   */
  @Get('callback/google')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({ summary: 'Google OAuth callback' })
  async googleCallback(@Req() req: Request & { user: UserEntity }, @Res() res: Response) {
    const token = this.authService.generateAccessToken(req.user);
    const frontendUrl = this.config.get<string>('FRONTEND_URL') || 'http://localhost:3001';
    // Redirect to frontend with token
    res.redirect(`${frontendUrl}/auth/callback?token=${token}`);
  }

  /**
   * Initiate GitHub OAuth login
   */
  @Get('github')
  @UseGuards(GithubAuthGuard)
  @ApiOperation({ summary: 'Initiate GitHub OAuth login' })
  async githubAuth() {
    // Guard redirects to GitHub
  }

  /**
   * GitHub OAuth callback
   */
  @Get('callback/github')
  @UseGuards(GithubAuthGuard)
  @ApiOperation({ summary: 'GitHub OAuth callback' })
  async githubCallback(@Req() req: Request & { user: UserEntity }, @Res() res: Response) {
    const token = this.authService.generateAccessToken(req.user);
    const frontendUrl = this.config.get<string>('FRONTEND_URL') || 'http://localhost:3001';
    // Redirect to frontend with token
    res.redirect(`${frontendUrl}/auth/callback?token=${token}`);
  }

  /**
   * Get current user profile (protected endpoint)
   */
  @Get('me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user profile' })
  async getCurrentUser(@Req() req: Request & { user: { userId: string } }) {
    const user = await this.authService.findUserById(req.user.userId);
    if (!user) {
      return { error: 'User not found' };
    }
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      avatar: user.avatar,
      provider: user.provider,
    };
  }

  /**
   * Generate API key for programmatic access
   */
  @Get('api-key')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Generate or retrieve API key' })
  async getApiKey(@Req() req: Request & { user: { userId: string } }) {
    const apiKey = await this.authService.generateApiKey(req.user.userId);
    return { apiKey };
  }
}
