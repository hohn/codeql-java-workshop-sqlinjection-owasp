import java

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
from MethodAccess ma, VarAccess arg
where
  ma.getMethod().hasQualifiedName("net.sqlcipher.database", "SQLiteDatabase", "rawQuery") and
  arg = ma.getArgument(0)
select ma, arg
