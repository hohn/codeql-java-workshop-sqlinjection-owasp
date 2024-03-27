/**
* @name SQL Injection in OWASP Security Shepard
* @kind path-problem
* @id java/sqlinjectionowasp
*/
	
import java 



// 3. Dataflow configuration.

/*
// 1. source 
// String CheckName = username.getText().toString();
from Method me, MethodAccess ma
where me.getName() = "getText" 
  and
  ma.getMethod() = me
select ma, "source"
*/

/*
// 2. sink: query part of 
// Cursor cursor = db.rawQuery(query, null);
from MethodAccess ma 
where ma.getMethod().getName() = "rawQuery"
select ma, ma.getArgument(0)
*/

import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph


class AndroidSQLInjection extends TaintTracking::Configuration {
	AndroidSQLInjection() { this = "AndroidSQLInjection" }

  // TODO add previous class and predicate definitions here
	override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof MyMA
    /*
		exists(Method me, MethodAccess ma |
       me.getName() = "getText" 
       and
       ma.getMethod() = me
      and 
      source.asExpr() = ma 
		)
    */
	}
 	 
  	override predicate isSink(DataFlow::Node sink) {
		exists(MethodAccess ma |
      ma.getMethod().getName() = "rawQuery"
      and 
		      sink.asExpr() = ma.getArgument(0)      
    )
		// sink.asExpr() instanceof Expr
    }

    override predicate isAdditionalTaintStep(DataFlow::Node node1,
          DataFlow::Node node2) {
            exists(MethodAccess ma |
              // 
              ma.getQualifier().getType().hasName("Editable") and
              ma.getMethod().hasName("toString") and
              node2.asExpr() = ma and
              node1.asExpr() = ma.getQualifier() // _.toString() 
              )
          

/* jump from
   username.getText()
 to 
   username.getText().toString();
 may be missing.
*/
          }
  }

class MyMA extends MethodAccess {
  MyMA () {
    this.getMethod().getName() = "getText"
  }
}

/* from MyMA ma
select ma
 */

 
from AndroidSQLInjection config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "SQL Injection"

/* 2.1 to 2.2 */
/*
 * from MethodAccess ma
 * where ma.getMethod().hasName("rawQuery")
 * select ma, ma.getMethod().getQualifiedName()
 */

/* hasQualifiedName("net.sqlcipher.database", "SQLLiteDatabase", "rawQuery") */
/* hasQualifiedName("net.sqlcipher.database", "SQLiteDatabase", "rawQuery") */
/*
 * from MethodAccess ma
 * where ma.getMethod().hasQualifiedName("net.sqlcipher.database", "SQLiteDatabase", "rawQuery")
 * select ma
 */

/* 2.2 */
