import { Module } from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { UserService } from "src/users/users.service";
import { AuthService } from "./auth.service";
import { JwtModule } from "@nestjs/jwt";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { JwtStrategy } from "./strats/jwt.strategy";


@Module({
    
    imports: [
    JwtModule.registerAsync({
        imports: [ConfigModule],
        useFactory: (configService: ConfigService) => {
        const secret = configService.get<string>('JWT_SECRET');
        console.log('JWT_SECRET from config:', secret);  // add this line to debug
        return {
            secret,
            signOptions: { expiresIn: configService.get<string>('JWT_EXPIRES_IN') }
        };
        },
        inject: [ConfigService],
    }),
    ],

    controllers: [AuthController],
    providers: [UserService, AuthService, JwtStrategy]
})
export class AuthModule{}