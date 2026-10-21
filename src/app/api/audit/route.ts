import { timingSafeEqual } from 'node:crypto'
import { AuditError, runAudit } from '@server/audit'
import { clientIp, takeRateLimit, withSlot } from '@server/limits'
import { pagespeedConfig } from '@server/settings'
import { getSettings, saveReport } from '@server/store'
import { jsonError, streamEvents } from '@server/stream'
import type { AuditProgress, ReportSource } from '@shared/types'

export const dynamic = 'force-dynamic'
export const maxDuration = 300

const SOURCES: ReportSource[] = ['web', 'api']

function hasValidApiToken(request: Request): boolean {
	const expected = process.env.OPENSEO_API_TOKEN

	// Preserve existing local behavior when no token is configured.
	if (!expected) return true

	const authorization = request.headers.get('authorization') ?? ''
	const match = /^Bearer\s+(.+)$/i.exec(authorization)

	if (!match) return false

	const suppliedBuffer = Buffer.from(match[1], 'utf8')
	const expectedBuffer = Buffer.from(expected, 'utf8')

	if (suppliedBuffer.length !== expectedBuffer.length) return false

	return timingSafeEqual(suppliedBuffer, expectedBuffer)
}

/**
 * POST /api/audit { url, source?, stream? }
 *
 * Streams progress as newline-delimited JSON and ends with { type: "done", id }.
 * Send stream: false to wait for the whole report as JSON instead.
 */
export async function POST(request: Request): Promise<Response> {
	if (!hasValidApiToken(request)) {
		return jsonError('Unauthorized.', 401)
	}

	const body = (await request.json().catch(() => ({}))) as Record<string, unknown>
	const url = typeof body.url === 'string' ? body.url : ''
	const source = SOURCES.includes(body.source as ReportSource)
		? (body.source as ReportSource)
		: 'api'
	const settings = await getSettings()

	if (!url.trim()) return jsonError('Enter a website address to audit.', 400)

	if (!takeRateLimit(clientIp(request))) {
		return jsonError("You've run a lot of audits. Try again in an hour.", 429)
	}

	const audit = (onProgress?: (progress: AuditProgress) => void) =>
		withSlot(async () => {
			const report = await runAudit(url, {
				source,
				onProgress,
				pagespeed: pagespeedConfig(settings),
				brokenLinkLimit: settings.brokenLinkLimit
			})

			await saveReport(report)
			return report
		})

	if (body.stream === false) {
		try {
			return Response.json(await audit())
		} catch (e) {
			return jsonError(e instanceof AuditError ? e.message : 'The audit failed.', 422)
		}
	}

	return streamEvents(async (send) => {
		send({ type: 'progress', step: 'queued', label: 'Starting the audit', pct: 1 })

		const report = await audit((p) => send({ type: 'progress', ...p }))

		send({ type: 'done', id: report.id, score: report.score, grade: report.grade })
	})
}
