import { Test, TestingModule } from '@nestjs/testing';
import { RetirementController } from './retirement.controller';

describe('RetirementController', () => {
  let controller: RetirementController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [RetirementController],
    }).compile();

    controller = module.get<RetirementController>(RetirementController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
