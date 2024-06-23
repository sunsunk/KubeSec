import { TestBed, inject } from '@angular/core/testing';
import { TagRetentionService } from './tag-retention.service';

describe('TagRetentionService', () => {
    beforeEach(() => {
        TestBed.configureTestingModule({
            providers: [TagRetentionService],
        });
    });

    it('should be created', inject(
        [TagRetentionService],
        (service: TagRetentionService) => {
            expect(service).toBeTruthy();
        }
    ));
});
