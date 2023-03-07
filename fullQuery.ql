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

  override predicate isSource(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("android.widget", "EditText", "getText") and
      node.asExpr() = ma
    )
  }

  override predicate isSink(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma.getMethod().hasQualifiedName("net.sqlcipher.database", "SQLiteDatabase", "rawQuery") and
      node.asExpr() = ma.getArgument(0)
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(MethodAccess ma |
      ma.getQualifier().getType().hasName(["Editable"]) and
      ma.getMethod().hasName("toString") and
      node1.asExpr() = ma.getQualifier() and
      node2.asExpr() = ma
    )
  }
}

from AndroidSQLInjection config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "SQL Injection"
