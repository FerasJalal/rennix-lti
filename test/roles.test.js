const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mapLtiRolesToInternalRole } = require('../src/lti/roles');

test('membership#Instructor maps to course_supervisor', () => {
  const role = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor';
  assert.equal(mapLtiRolesToInternalRole([role]), 'course_supervisor');
});

test('system/person#Administrator maps to course_supervisor', () => {
  const role = 'http://purl.imsglobal.org/vocab/lis/v2/system/person#Administrator';
  assert.equal(mapLtiRolesToInternalRole([role]), 'course_supervisor');
});

test('membership#TeachingAssistant maps to section_instructor (regression: used to silently fall through to student)', () => {
  const role = 'http://purl.imsglobal.org/vocab/lis/v2/membership#TeachingAssistant';
  assert.equal(mapLtiRolesToInternalRole([role]), 'section_instructor');
});

test('membership#ContentDeveloper maps to section_instructor', () => {
  const role = 'http://purl.imsglobal.org/vocab/lis/v2/membership#ContentDeveloper';
  assert.equal(mapLtiRolesToInternalRole([role]), 'section_instructor');
});

test('membership#Learner maps to student', () => {
  const role = 'http://purl.imsglobal.org/vocab/lis/v2/membership#Learner';
  assert.equal(mapLtiRolesToInternalRole([role]), 'student');
});

test('unknown role falls back to student', () => {
  assert.equal(mapLtiRolesToInternalRole(['http://example.com/some/other#Role']), 'student');
});

test('missing/empty roles falls back to student', () => {
  assert.equal(mapLtiRolesToInternalRole(undefined), 'student');
  assert.equal(mapLtiRolesToInternalRole([]), 'student');
});

test('supervisor role wins when multiple roles present', () => {
  const roles = [
    'http://purl.imsglobal.org/vocab/lis/v2/membership#Learner',
    'http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor',
  ];
  assert.equal(mapLtiRolesToInternalRole(roles), 'course_supervisor');
});

const M = 'http://purl.imsglobal.org/vocab/lis/v2/membership';
const { isInstructorRole } = require('../src/lti/roles');

test('TA sent as a sub-role of Instructor maps to section_instructor, not course_supervisor or student', () => {
  assert.equal(mapLtiRolesToInternalRole([`${M}/Instructor#TeachingAssistant`]), 'section_instructor');
  assert.equal(mapLtiRolesToInternalRole([`${M}/Instructor#Grader`]), 'section_instructor');
});

test('owning Instructor sub-roles (e.g. PrimaryInstructor, Lecturer) map to course_supervisor', () => {
  assert.equal(mapLtiRolesToInternalRole([`${M}/Instructor#PrimaryInstructor`]), 'course_supervisor');
  assert.equal(mapLtiRolesToInternalRole([`${M}/Instructor#Lecturer`]), 'course_supervisor');
});

test('LTI 1.1-style short role names are understood', () => {
  assert.equal(mapLtiRolesToInternalRole(['Instructor']), 'course_supervisor');
  assert.equal(mapLtiRolesToInternalRole(['TeachingAssistant']), 'section_instructor');
  assert.equal(mapLtiRolesToInternalRole(['Learner']), 'student');
  assert.equal(mapLtiRolesToInternalRole(['Mentor']), 'observer');
});

test('a Mentor who is not also a Learner is an observer; a Mentor+Learner is a student', () => {
  assert.equal(mapLtiRolesToInternalRole([`${M}#Mentor`]), 'observer');
  assert.equal(mapLtiRolesToInternalRole([`${M}/Mentor#Advisor`]), 'observer');
  assert.equal(mapLtiRolesToInternalRole([`${M}#Mentor`, `${M}#Learner`]), 'student');
});

test('learner sub-roles stay students', () => {
  assert.equal(mapLtiRolesToInternalRole([`${M}/Learner#NonCreditLearner`]), 'student');
});

test('only the two instructor-tier roles count as instructors', () => {
  assert.equal(isInstructorRole('course_supervisor'), true);
  assert.equal(isInstructorRole('section_instructor'), true);
  for (const r of ['student', 'observer', 'dropped', undefined]) assert.equal(isInstructorRole(r), false, String(r));
});
