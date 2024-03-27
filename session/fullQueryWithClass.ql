/**
 * @name SQL Injection in OWASP Security Shepard
 * @kind path-problem
 * @id java/sqlinjectionowasp
 */

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class AndroidSQLInjection extends TaintTracking::Configuration {
  AndroidSQLInjection() { this = "AndroidSQLInjection" }

  override predicate isSource(DataFlow::Node source) { source.asExpr() instanceof GetTextAccess }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "rawQuery" and
      sink.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma |
      //
      ma.getQualifier().getType().hasName("Editable") and
      ma.getMethod().hasName("toString") and
      node2.asExpr() = ma and
      node1.asExpr() = ma.getQualifier() // _.toString()
    )
  }
}

class GetTextAccess extends MethodAccess {
  GetTextAccess() { this.getMethod().getName() = "getText" }
}

from AndroidSQLInjection config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "SQL Injection"
