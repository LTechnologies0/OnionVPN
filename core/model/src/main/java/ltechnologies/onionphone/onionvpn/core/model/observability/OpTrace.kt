package ltechnologies.onionphone.onionvpn.core.model.observability

import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilitySeverity

/**
 * Structured pipeline / module-boundary tracer.
 *
 * Emits `module.step start|ok|fail durationMs=…` when [DiagnosticsGate] is enabled;
 * otherwise runs [block] with zero diagnostic allocation.
 */
object OpTrace {
    fun interface Sink {
        fun emit(
            level: ProcessLogLevel,
            module: String,
            message: String,
            error: Throwable?,
        )
    }

    @Volatile
    var sink: Sink? = null

    fun event(
        module: String,
        message: String,
        level: ProcessLogLevel = ProcessLogLevel.DEBUG,
        error: Throwable? = null,
    ) {
        if (!DiagnosticsGate.enabled()) return
        sink?.emit(level, module, message, error)
    }

    fun trace(module: String, message: String) =
        event(module, message, ProcessLogLevel.TRACE)

    fun debug(module: String, message: String) =
        event(module, message, ProcessLogLevel.DEBUG)

    fun info(module: String, message: String) =
        event(module, message, ProcessLogLevel.INFO)

    fun warn(module: String, message: String, error: Throwable? = null) =
        event(module, message, ProcessLogLevel.WARN, error)

    fun error(module: String, message: String, error: Throwable? = null) =
        event(module, message, ProcessLogLevel.ERROR, error)

    inline fun <T> step(
        module: String,
        name: String,
        level: ProcessLogLevel = ProcessLogLevel.DEBUG,
        block: () -> T,
    ): T {
        if (!DiagnosticsGate.enabled()) return block()
        val t0 = System.nanoTime()
        event(module, "$name start", level)
        return try {
            val result = block()
            val ms = (System.nanoTime() - t0) / 1_000_000L
            event(module, "$name ok durationMs=$ms", level)
            result
        } catch (error: Throwable) {
            val ms = (System.nanoTime() - t0) / 1_000_000L
            event(module, "$name fail durationMs=$ms", ProcessLogLevel.ERROR, error)
            throw error
        }
    }

    suspend inline fun <T> stepSuspending(
        module: String,
        name: String,
        level: ProcessLogLevel = ProcessLogLevel.DEBUG,
        block: suspend () -> T,
    ): T {
        if (!DiagnosticsGate.enabled()) return block()
        val t0 = System.nanoTime()
        event(module, "$name start", level)
        return try {
            val result = block()
            val ms = (System.nanoTime() - t0) / 1_000_000L
            event(module, "$name ok durationMs=$ms", level)
            result
        } catch (error: Throwable) {
            val ms = (System.nanoTime() - t0) / 1_000_000L
            event(module, "$name fail durationMs=$ms", ProcessLogLevel.ERROR, error)
            throw error
        }
    }
}

fun ProcessLogLevel.toStabilitySeverity(): StabilitySeverity = severity
