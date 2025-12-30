import { Test, TestingModule } from '@nestjs/testing';
import { RetirementService } from './retirement.service';

describe('RetirementService', () => {
  let service: RetirementService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [RetirementService],
    }).compile();

    service = module.get<RetirementService>(RetirementService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
