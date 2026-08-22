import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { UsersService } from './users.service';
import {
  CreateUserDto,
  UpdateUserDto,
  UserParamsDto,
  UserQueryDto,
  UserDataResponse,
  UserListResponseDto,
} from './dto';
import { ErrorResponse } from '@common/dto';
import { Roles, ResponseMessage, CurrentUser } from '@common/decorators';
import { AuthGuard } from '@common/guards';

@ApiTags('Users')
@ApiBearerAuth()
@Controller('users')
@ApiResponse({ status: 401, description: 'Unauthorized', type: ErrorResponse })
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('profile')
  @UseGuards(AuthGuard)
  @ResponseMessage('Profile retrieved successfully')
  @ApiOperation({ summary: 'Get current authenticated user profile' })
  @ApiResponse({
    status: 200,
    description: 'Own user profile',
    type: UserDataResponse,
  })
  getProfile(@CurrentUser('id') userId: string) {
    return this.usersService.getUserWithProfile(userId);
  }

  @Post()
  @Roles('system_admin', 'ADMIN')
  @HttpCode(HttpStatus.CREATED)
  @ResponseMessage('User created successfully')
  @ApiOperation({ summary: 'Create a new user (admin only)' })
  @ApiResponse({
    status: 201,
    description: 'User created successfully',
    type: UserDataResponse,
  })
  @ApiResponse({
    status: 422,
    description: 'Validation error',
    type: ErrorResponse,
  })
  @ApiResponse({ status: 403, description: 'Forbidden', type: ErrorResponse })
  @ApiResponse({
    status: 409,
    description: 'Email already exists',
    type: ErrorResponse,
  })
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Get()
  @Roles('system_admin', 'ADMIN', 'content_admin')
  @ResponseMessage('OK')
  @ApiOperation({ summary: 'List all users (paginated)' })
  @ApiResponse({
    status: 200,
    description: 'Paginated list of users',
    type: UserListResponseDto,
  })
  findAll(@Query() query: UserQueryDto) {
    return this.usersService.findAll(query);
  }

  @Get(':id')
  @Roles('system_admin', 'ADMIN', 'content_admin')
  @ResponseMessage('OK')
  @ApiOperation({ summary: 'Get user by ID (admin only)' })
  @ApiParam({ name: 'id', description: 'User ID (UUID)' })
  @ApiResponse({
    status: 200,
    description: 'User found',
    type: UserDataResponse,
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
    type: ErrorResponse,
  })
  findOne(@Param() params: UserParamsDto) {
    return this.usersService.findOne(params.id);
  }

  @Patch(':id')
  @Roles('system_admin', 'ADMIN')
  @ResponseMessage('User updated successfully')
  @ApiOperation({ summary: 'Update user' })
  @ApiParam({ name: 'id', description: 'User ID (UUID)' })
  @ApiResponse({
    status: 200,
    description: 'User updated',
    type: UserDataResponse,
  })
  @ApiResponse({
    status: 422,
    description: 'Validation error',
    type: ErrorResponse,
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
    type: ErrorResponse,
  })
  update(@Param() params: UserParamsDto, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(params.id, updateUserDto);
  }

  @Delete(':id')
  @Roles('system_admin', 'ADMIN')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete user (admin only)' })
  @ApiParam({ name: 'id', description: 'User ID (UUID)' })
  @ApiResponse({ status: 204, description: 'User deleted' })
  @ApiResponse({ status: 403, description: 'Forbidden', type: ErrorResponse })
  @ApiResponse({
    status: 404,
    description: 'User not found',
    type: ErrorResponse,
  })
  remove(@Param() params: UserParamsDto) {
    return this.usersService.remove(params.id);
  }
}
