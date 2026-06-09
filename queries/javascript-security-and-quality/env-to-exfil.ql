/**
 * @name Environment Variables Flowing To Exfiltration Sinks
 * @description Tracks data flow from process.env to exfiltration-relevant sinks.
 * @kind path-problem
 * @id custom/js/env-to-exfil
 * @problem.severity warning
 * @security-severity 8.0
 * @precision medium
 * @tags security
 *       external/cwe/cwe-200
 */

import javascript
import semmle.javascript.dataflow.TaintTracking

module EnvToExfilConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = DataFlow::globalVarRef("process").getAPropertyRead("env").getAPropertyRead()
    or
    source = DataFlow::globalVarRef("process").getAPropertyRead("env").getAPropertyReference()
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Taint from object-literal property values to the object itself.
    exists(DataFlow::ObjectLiteralNode obj |
      succ = obj and
      obj.getAPropertySource() = pred
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // Common HTTP exfil sinks.
    sink = DataFlow::globalVarRef("fetch").getACall().getArgument(0)
    or
    sink = DataFlow::globalVarRef("fetch").getACall().getArgument(1)
    or
    sink = DataFlow::globalVarRef("JSON").getAPropertyRead("stringify").getACall().getArgument(0)
    or
    sink = DataFlow::moduleMember("axios", "post").getACall().getArgument(1)
    or
    sink = DataFlow::moduleMember("axios", "put").getACall().getArgument(1)
    or
    sink = DataFlow::moduleMember("http", "request").getACall().getArgument(0)
    or
    sink = DataFlow::moduleMember("https", "request").getACall().getArgument(0)

    // High-risk execution sinks where env may get embedded in command strings.
    or sink = DataFlow::moduleMember("child_process", "exec").getACall().getArgument(0)
    or sink = DataFlow::moduleMember("child_process", "execSync").getACall().getArgument(0)
  }
}

module EnvToExfilFlow = TaintTracking::Global<EnvToExfilConfig>;

import EnvToExfilFlow::PathGraph

from EnvToExfilFlow::PathNode source, EnvToExfilFlow::PathNode sink
where EnvToExfilFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Data from environment variables reaches an exfiltration-related sink."
