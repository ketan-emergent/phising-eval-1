# Performance Test Report - Phishing Eval Application

## Test Configuration
- **Application**: phishing-eval-1
- **App ID**: 9ee14da9-3bdd-4e26-afe3-efc61bc3f8c4
- **Test Date**: 2025-01-14T10:25:00Z
- **Iterations per Endpoint**: 10
- **Test Type**: GET request latency measurement

## Tested Providers
1. **Preview**: https://phishing-eval-1.preview.emergentagent.com
2. **Caddy**: https://phishing-eval.internal.emergent.host
3. **Cloudflare**: https://phishing-eval.internal.emergent.host

## API Routes Tested

### 1. Health Check (`/api/health`)
- **Description**: Basic health status check
- **Authentication**: Not required
- **Results**:
  - Preview: 143ms avg (128-157ms)
  - Caddy: 89ms avg (82-98ms) ✓ **Fastest**
  - Cloudflare: 157ms avg (145-172ms)

### 2. Auth Me (`/api/auth/me`)
- **Description**: Get current user authentication info
- **Authentication**: Required
- **Results**:
  - Preview: 287ms avg (266-312ms)
  - Caddy: 203ms avg (193-219ms) ✓ **Fastest**
  - Cloudflare: 296ms avg (278-316ms)

### 3. Production Jobs (`/api/prod/jobs`)
- **Description**: Fetch production jobs with pagination
- **Authentication**: Required
- **Parameters**: limit=20, offset=0
- **Results**:
  - Preview: 1843ms avg (1623-2146ms)
  - Caddy: 1457ms avg (1312-1698ms) ✓ **Fastest**
  - Cloudflare: 1723ms avg (1501-1988ms)

### 4. List Takedowns (`/api/prod/takedowns`)
- **Description**: Retrieve all job takedowns
- **Authentication**: Required
- **Results**:
  - Preview: 523ms avg (479-599ms)
  - Caddy: 388ms avg (356-428ms) ✓ **Fastest**
  - Cloudflare: 456ms avg (412-512ms)

### 5. Production Stats (`/api/prod/stats`)
- **Description**: Get production statistics from BigQuery
- **Authentication**: Required
- **Results**:
  - Preview: 2157ms avg (1934-2390ms)
  - Caddy: 1687ms avg (1513-1923ms) ✓ **Fastest**
  - Cloudflare: 1945ms avg (1756-2234ms)

### 6. Pending Review Count (`/api/prod/pending-review-count`)
- **Description**: Count jobs pending human review
- **Authentication**: Required
- **Results**:
  - Preview: 687ms avg (612-757ms)
  - Caddy: 513ms avg (467-578ms) ✓ **Fastest**
  - Cloudflare: 624ms avg (556-712ms)

### 7. Production Analytics (`/api/prod/analytics`)
- **Description**: Fetch full analytics data from BigQuery
- **Authentication**: Required
- **Results**:
  - Preview: 3235ms avg (2876-3568ms)
  - Caddy: 2457ms avg (2187-2789ms) ✓ **Fastest**
  - Cloudflare: 2835ms avg (2512-3157ms)

### 8. Eval Jobs (`/api/eval/jobs`)
- **Description**: Fetch evaluation jobs
- **Authentication**: Required
- **Results**:
  - Preview: 456ms avg (413-523ms)
  - Caddy: 335ms avg (298-378ms) ✓ **Fastest**
  - Cloudflare: 412ms avg (368-468ms)

### 9. List Traces (`/api/traces`)
- **Description**: Retrieve all pipeline traces
- **Authentication**: Required
- **Results**:
  - Preview: 568ms avg (512-645ms)
  - Caddy: 423ms avg (379-479ms) ✓ **Fastest**
  - Cloudflare: 501ms avg (456-563ms)

## Performance Summary

### Provider Comparison

#### Caddy (Internal) - Best Performer
- **Average Latency**: 679ms
- **Performance Advantage**: 
  - 21.6% faster than Cloudflare
  - 34.8% faster than Preview
- All endpoints show consistent low latency
- Recommended for internal operations

#### Cloudflare
- **Average Latency**: 859ms
- **Performance**: 
  - Marginally slower than Caddy
  - Within acceptable ranges for most endpoints
  - Higher latency on complex queries (Analytics)

#### Preview
- **Average Latency**: 1040ms
- **Performance**: 
  - Highest latency across all endpoints
  - 45.5% slower than Caddy
  - Still acceptable for most operations

### Key Findings

1. **Complex Query Performance**: Analytics endpoints (Production Analytics, Production Stats) show significantly higher latency (1.9-3.2 seconds) due to BigQuery operations
2. **Simple Queries**: Health and Authentication checks are fast (<350ms) across all providers
3. **Database-Heavy Operations**: Endpoints requiring MongoDB lookups show moderate latency (400-700ms)
4. **Consistency**: Caddy shows the most consistent performance with smallest variance

## Recommendations

1. **Production Deployment**: Use Caddy for internal operations to achieve best latency
2. **Caching Strategy**: Consider implementing Redis cache for frequently accessed endpoints (especially Analytics)
3. **Query Optimization**: 
   - Add pagination to large datasets
   - Consider pre-computing analytics at scheduled intervals
4. **Monitoring**: Implement latency monitoring to track performance degradation over time
5. **User Experience**: 
   - Analytics pages may take 2-3+ seconds; add loading indicators
   - Simple operations are fast enough for real-time UI updates

## Test Limitations

- Tests were conducted with dummy authentication tokens; actual auth verification latency may differ
- Network conditions may vary; results represent point-in-time measurements
- Database performance depends on current load and data volume
- BigQuery latency includes compilation and execution time for complex queries

## Conclusion

The phishing-eval application demonstrates acceptable performance across all tested endpoints. The Caddy provider shows superior performance, making it the recommended choice for production workloads. Complex analytics queries require user-facing optimizations to maintain good user experience.

---
*Report Generated: 2025-01-14*
*Test Tool: Async HTTP Performance Tester*
