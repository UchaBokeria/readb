package dev.readb.companion;
public final class PermissionFlowTest {
 private static void expect(PermissionFlow.Step actual,PermissionFlow.Step expected){if(actual!=expected)throw new AssertionError(actual+" != "+expected);}
 public static void main(String[] args){
  PermissionFlow denied=new PermissionFlow();
  expect(denied.next(false,false,false,false),PermissionFlow.Step.RUNTIME);
  expect(denied.next(false,false,false,false),PermissionFlow.Step.NOTIFICATIONS);
  expect(denied.next(false,false,false,false),PermissionFlow.Step.VPN);
  expect(denied.next(false,false,false,false),PermissionFlow.Step.DEBUG_SETTINGS);
  expect(denied.next(false,false,false,false),PermissionFlow.Step.DONE);
  expect(denied.next(false,false,false,false),PermissionFlow.Step.DONE);
  expect(new PermissionFlow().next(true,true,true,true),PermissionFlow.Step.DONE);
  PermissionFlow partial=new PermissionFlow();
  expect(partial.next(true,true,false,true),PermissionFlow.Step.VPN);
  expect(partial.next(true,true,false,true),PermissionFlow.Step.DONE);
  PermissionFlow granted=new PermissionFlow();
  expect(granted.next(false,true,false,false),PermissionFlow.Step.RUNTIME);
  expect(granted.next(true,true,false,false),PermissionFlow.Step.VPN);
  expect(granted.next(true,true,true,false),PermissionFlow.Step.DEBUG_SETTINGS);
  expect(granted.next(true,true,true,true),PermissionFlow.Step.DONE);
  System.out.println("Permission grant/deny/skip/no-loop checks passed");
 }
}
