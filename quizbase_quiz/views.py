from django.shortcuts import render
from rest_framework import generics, status
from .models import Question, Answer
from rest_framework.response import Response
from .serializers import QuestionSerializer, AnswerSerializer, QuestionSubSerializer
from account.api.base.permissions import AuthUserIsLogistic


class QuestionListView(generics.ListAPIView):
    permission_classes = (AuthUserIsLogistic,)
    serializer_class = QuestionSerializer

    def get_queryset(self):
        return Question.objects.filter(user=self.request.user)
    
class AnswerListView(generics.ListAPIView):
    permission_classes = (AuthUserIsLogistic,)
    serializer_class = AnswerSerializer

    def get_queryset(self):
        return Answer.objects.filter(user=self.request.user)
    


class ScoreView(generics.CreateAPIView):
    permission_classes = (AuthUserIsLogistic,)
    serializer_class = QuestionSubSerializer

    def post(self, request, *args, **kwargs):
        answer_choice = request.data.get('answer_choice')
        question_id = request.data.get('question')
        question = Question.objects.get(id=question_id)
        correct_answer = Answer.objects.get(
            question=question, answer_choice=answer_choice)
        score = 0

        if correct_answer:
            score += 1

        total_questions = Question.objects.count()
        percentage_score = (score / total_questions) * 100

        return Response(
            {
            'score': score,
            'percentage_score': percentage_score
            },
            status=status.HTTP_200_OK
        )