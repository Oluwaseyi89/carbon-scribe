import { Injectable, Logger } from '@nestjs/common';
import { CarbonAssetService } from '../stellar/soroban/contracts/carbon-asset.service';
import { IdempotencyService } from '../stellar/soroban/idempotency/idempotency.service';
import { DuplicateStrategy } from '../stellar/soroban/interfaces/idempotency.interface';

@Injectable()
export class RetirementService {
  private readonly logger = new Logger(RetirementService.name);

  constructor(
    private readonly carbonAssetService: CarbonAssetService,
    private readonly idempotencyService: IdempotencyService,
  ) {}

  /**
   * Retire credits with idempotency support
   *
   * @param companyId - The company ID for the retirement
   * @param userId - The user ID performing the retirement
   * @param creditId - The credit ID to retire
   * @param amount - The amount of credits to retire
   * @param purpose - The purpose of the retirement
   * @returns Retirement result with idempotency information
   */
  async retireCredits(
    companyId: string,
    userId: string,
    creditId: string,
    amount: number,
    purpose: string,
  ): Promise<any> {
    const workflowId = `retirement-${creditId}-${Date.now()}`;

    this.logger.log(`Processing retirement for workflow ${workflowId}`, {
      companyId,
      userId,
      creditId,
      amount,
      purpose,
    });

    // Check if already processed
    const isProcessed = await this.idempotencyService.isWorkflowProcessed(
      companyId,
      workflowId,
      'retire',
    );

    if (isProcessed) {
      // Return cached result
      const call = await this.idempotencyService.getContractCallByWorkflow(
        companyId,
        workflowId,
        'retire',
      );

      this.logger.log(`Returning cached result for workflow ${workflowId}`);

      return {
        success: true,
        cached: true,
        transactionHash: call.transactionHash,
        result: call.result,
        workflowId,
        callId: call.id,
      };
    }

    try {
      // Execute with idempotency - added companyId to the payload
      const result = await this.carbonAssetService.invokeWithIdempotency(
        companyId,
        {
          companyId, // <-- Added missing companyId property
          methodName: 'retire',
          args: [
            { type: 'u32', value: parseInt(creditId, 10) },
            { type: 'u32', value: amount },
          ],
        },
        {
          workflowId,
          metadata: { userId, purpose, creditId },
        },
        DuplicateStrategy.RETURN_CACHED,
      );

      this.logger.log(`Retirement completed for workflow ${workflowId}`, {
        transactionHash: result.transactionHash,
        isDuplicate: result.isDuplicate,
        isCached: result.isCached,
      });

      return {
        success: true,
        cached: result.isCached,
        isDuplicate: result.isDuplicate,
        transactionHash: result.transactionHash,
        callId: result.callId,
        workflowId: result.workflowId,
        result: result.result,
        // 💡 FIXED: Forward the originalCallId field to pass the duplicate handling test
        originalCallId: result.originalCallId,
      };
    } catch (error) {
      this.logger.error(`Retirement failed for workflow ${workflowId}`, {
        error: error.message,
        stack: error.stack,
      });
      throw error;
    }
  }

  /**
   * Get retirement status by workflow ID
   */
  async getRetirementStatus(
    companyId: string,
    workflowId: string,
  ): Promise<any> {
    const call = await this.idempotencyService.getContractCallByWorkflow(
      companyId,
      workflowId,
      'retire',
    );

    if (!call) {
      return {
        found: false,
        status: 'NOT_FOUND',
        workflowId,
      };
    }

    return {
      found: true,
      status: call.status,
      transactionHash: call.transactionHash,
      result: call.result,
      submittedAt: call.submittedAt,
      confirmedAt: call.confirmedAt,
      isDuplicate: call.isDuplicate,
      workflowId: call.workflowId,
    };
  }

  /**
   * Check if a retirement has been processed
   */
  async isRetirementProcessed(
    companyId: string,
    workflowId: string,
  ): Promise<boolean> {
    return this.idempotencyService.isWorkflowProcessed(
      companyId,
      workflowId,
      'retire',
    );
  }
}
