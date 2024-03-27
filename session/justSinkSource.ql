/**
 * @name SQL Injection in OWASP Security Shepard
 * @ kind problem
 * @kind problem
 * @id java/sqlinjectionowasp
 */

import java
import semmle.code.java.dataflow.TaintTracking

class AndroidSQLInjection extends TaintTracking::Configuration {
  AndroidSQLInjection() { this = "AndroidSQLInjection" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("getText") and
      source.asExpr() = ma
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma, VarAccess arg |
      ma.getMethod().hasQualifiedName("net.sqlcipher.database", "SQLiteDatabase", "rawQuery") and
      arg = ma.getArgument(0) and
      sink.asExpr() = arg
    )
  }
}

from AndroidSQLInjection config, DataFlow::Node source, DataFlow::Node sink
where config.hasFlow(source, sink)
select sink, "to", source, "from"
