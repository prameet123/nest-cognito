import { Injectable, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { createHmac } from 'node:crypto';

@Injectable()
export class AuthService {
  private readonly cognito: CognitoIdentityProviderClient;

  constructor(private readonly config: ConfigService) {
    this.cognito = new CognitoIdentityProviderClient({
      region: this.config.getOrThrow<string>('AWS_REGION'),
    });
  }
  private calculateSecretHash(username: string): string {
    const clientId = this.config.getOrThrow<string>('COGNITO_CLIENT_ID');

    const clientSecret = this.config.getOrThrow<string>(
      'COGNITO_CLIENT_SECRET',
    );

    return createHmac('sha256', clientSecret)
      .update(username + clientId)
      .digest('base64');
  }
  async signUp(email: string, password: string) {
    const clientId = this.config.getOrThrow<string>('COGNITO_CLIENT_ID');
    const secretHash = this.calculateSecretHash(email);

    try {
      const result = await this.cognito.send(
        new SignUpCommand({
          ClientId: clientId,
          Username: email,
          Password: password,
          SecretHash: secretHash,
          UserAttributes: [{ Name: 'email', Value: email }],
        }),
      );

      return {
        message: 'Signup request processed. Check your email for confirmation.',
        userConfirmed: result.UserConfirmed ?? false,
        userSub: result.UserSub,
        codeDeliveryDetails: result.CodeDeliveryDetails
          ? {
              destination: result.CodeDeliveryDetails.Destination,
              deliveryMedium: result.CodeDeliveryDetails.DeliveryMedium,
            }
          : undefined,
      };
    } catch (error) {
      // Don't expose raw AWS errors or passwords to clients.
      if (
        error instanceof Error &&
        [
          'UsernameExistsException',
          'InvalidPasswordException',
          'InvalidParameterException',
          'CodeDeliveryFailureException',
        ].includes(error.name)
      ) {
        throw new BadRequestException(error.message);
      }

      throw error;
    }
  }

  async confirmSignUp(email: string, confirmationCode: string) {
    const clientId = this.config.getOrThrow<string>('COGNITO_CLIENT_ID');

    await this.cognito.send(
      new ConfirmSignUpCommand({
        ClientId: clientId,
        SecretHash: this.calculateSecretHash(email),
        Username: email,
        ConfirmationCode: confirmationCode,
      }),
    );

    return {
      message: 'Email confirmed successfully. Your account is now verified.',
    };
  }

  async login(email: string, password: string) {
    const clientId = this.config.getOrThrow<string>('COGNITO_CLIENT_ID');
    try {
      const result = await this.cognito.send(
        new InitiateAuthCommand({
          AuthFlow: 'USER_PASSWORD_AUTH',
          ClientId: clientId,
          AuthParameters: {
            USERNAME: email,
            PASSWORD: password,
            SECRET_HASH: this.calculateSecretHash(email),
          },
        }),
      );

      // Cognito can return a challenge instead of tokens.
      if (result.ChallengeName) {
        return {
          message: 'Additional authentication is required.',
          challengeName: result.ChallengeName,
          session: result.Session,
          challengeParameters: result.ChallengeParameters,
        };
      }

      const tokens = result.AuthenticationResult;

      if (!tokens) {
        throw new Error('Cognito did not return authentication tokens.');
      }

      return {
        accessToken: tokens.AccessToken,
        idToken: tokens.IdToken,
        refreshToken: tokens.RefreshToken,
        expiresIn: tokens.ExpiresIn,
        tokenType: tokens.TokenType,
      };
    } catch (error) {
      // Don't expose raw AWS errors or passwords to clients.
      if (
        error instanceof Error &&
        [
          'NotAuthorizedException',
          'UserNotFoundException',
          'InvalidPasswordException',
        ].includes(error.name)
      ) {
        throw new BadRequestException(error.message);
      }

      throw error;
    }
  }
}
