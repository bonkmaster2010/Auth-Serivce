import { Body, Controller, Get, Post, Req, UseGuards } from "@nestjs/common";
import { RegisterDto } from "./dto/register.dto";
import { AuthService } from "./auth.service";
import { LoginDto } from "./dto/login.dto";
import { JwtAuthGuard } from "./guards/auth.guard";
import { forgotPasswordDto } from "./dto/forgotPassword.dto";
import { resetPasswordDto } from "./dto/resetPassword.dto";




@Controller()
export class AuthController{
     constructor(private authService: AuthService){}

    @Post('register')
    async register(@Body() data: RegisterDto){
       return await this.authService.register(data.username, data.email, data.password);
    };

    @Post('login')
    async login(@Body() data: LoginDto){
        return await this.authService.login(data.email, data.password)
    };

    @Post('refresh')
    async refresh(@Body() body: {refresh_token: string}){
        return await this.authService.refresh(body.refresh_token)
    };

    @Post('logout')
    logout(@Body() body: {refresh_token: string}){
        return this.authService.logout(body.refresh_token)
    };

    @UseGuards(JwtAuthGuard)
    @Get('profile')
    getProfile(@Req() req){
        return req.user
    }

    @Post('forgot-password')
    forgotPassword(@Body() body: forgotPasswordDto){
        return this.authService.forgotPassword(body.email);
    };

    @Post('reset-password')
    async resetPassword(@Body() dto: resetPasswordDto){
        const { resetToken, email, newPassword } = dto;
        const result = await this.authService.resetPassword(email, resetToken, newPassword);
        return {message: result}
    }

}