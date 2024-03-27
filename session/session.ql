import java

from MethodAccess ma 
where ma.getMethod().hasQualifiedName("android.widget", "EditText", "getText") 
select ma