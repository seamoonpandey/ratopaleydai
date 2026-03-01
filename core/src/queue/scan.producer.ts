import { Injectable, Logger } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';

export const SCAN_QUEUE = 'scan';

@Injectable()
export class ScanQueueProducer {
  private readonly logger = new Logger(ScanQueueProducer.name);

  constructor(@InjectQueue(SCAN_QUEUE) private readonly queue: Queue) {}

  async enqueue(scanId: string): Promise<void> {
    await this.queue.add(
      'run-scan',
      { scanId },
      {
        attempts: 2,
        backoff: { type: 'exponential', delay: 2000 },
        removeOnComplete: 100,
        removeOnFail: 50,
      },
    );
    this.logger.log(`queued scan job scanId=${scanId}`);
  }
}
